#!/usr/bin/env node
import "fake-indexeddb/auto";
import { realpathSync } from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { Command } from "commander";
import { acquireProfileLock, isCanonicalMatrixUserId, profileDir, readSession } from "./profile.js";
import {
  markBackupWorkPending,
  openStorage,
  waitForBackupSettled,
  type OpenedStorage,
} from "./storage.js";
import { runAction, CommandResult, safeErrorMessage, safeOutputField } from "./output.js";
import { StorageError } from "@telecrypt-io/storage/core";
import * as core from "@telecrypt-io/storage/core";
import { loginAndInitialize } from "./loginTransaction.js";
import { logoutProfile } from "./logout.js";
import { assertTrustedHomeserver } from "./oidc.js";
import { cancellationExitCode, installCancellationHandlers } from "./cancellation.js";
import { scheduleBoundedNormalExit } from "./processExit.js";
import { readBoundedInput, writeBoundedDownload } from "./fileTransfer.js";
import { MAX_RECOVERY_KEY_BYTES, readRecoveryKey, requireRecoveryKey } from "./recoveryInput.js";

// matrix-js-sdk (loglevel) and the rust-crypto WASM tracing layer write
// verbose logs straight to console.log/debug/info/trace (stdout by default)
// AND console.warn/error (stderr by default) — e.g. push-rule setup notices
// and background-request warnings fire on totally successful runs. Left
// alone, that corrupts BOTH halves of the CLI's output contract: stdout must
// be exactly one line (human text or --json payload), and stderr under
// --json must be exactly one `{"error": "..."}` line for a test (or script)
// to parse. Silence all of them here, before TeleCryptIOStorage.create() ever
// triggers rust-crypto initialisation; the CLI's own output always goes
// through process.stdout.write/process.stderr.write directly (see
// output.ts), never console.*, so this can't swallow anything we emit.
console.log = () => {};
console.debug = () => {};
console.info = () => {};
console.trace = () => {};
console.warn = () => {};
console.error = () => {};

const EXT_MIMETYPES: Record<string, string> = {
  ".txt": "text/plain",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".pdf": "application/pdf",
  ".md": "text/markdown",
};
const MAX_RECOVERY_RESULT_COUNT = 100_000;
const MAX_LIST_RESULT_COUNT = 10_000;

function requireBoundedList<T>(value: T[], label: string): T[] {
  if (value.length > MAX_LIST_RESULT_COUNT) {
    throw new StorageError(`${label} returned too many entries`);
  }
  return value;
}

function withCoreDeadline<T>(
  opened: OpenedStorage,
  operation: (signal: AbortSignal) => Promise<T>,
  label: string,
): Promise<T> {
  return opened.run(operation, label);
}

function openProfileStorage(signal: AbortSignal): Promise<OpenedStorage> {
  return openStorage(undefined, signal);
}

async function withProfileStorage<T>(
  signal: AbortSignal,
  operation: (opened: OpenedStorage) => Promise<T>,
): Promise<T> {
  const opened = await openProfileStorage(signal);
  try {
    return await operation(opened);
  } finally {
    await opened.close();
  }
}

function guessMimetype(filePath: string): string {
  return EXT_MIMETYPES[path.extname(filePath).toLowerCase()] ?? "application/octet-stream";
}

interface RecoveryResult {
  recoveryKey?: string;
  imported?: number;
  total?: number;
}

function validateRecoveryResult(value: unknown): RecoveryResult {
  if (!value || typeof value !== "object") throw new StorageError("recovery operation returned an invalid result");
  const result = value as { recoveryKey?: unknown; imported?: unknown; total?: unknown };
  if (result.recoveryKey !== undefined) {
    if (typeof result.recoveryKey !== "string" || Buffer.byteLength(result.recoveryKey, "utf8") > MAX_RECOVERY_KEY_BYTES) {
      throw new StorageError("recovery setup returned an invalid recovery key");
    }
    requireRecoveryKey(result.recoveryKey);
  }
  for (const [name, count] of [["imported", result.imported], ["total", result.total]] as const) {
    if (
      count !== undefined &&
      (typeof count !== "number" || !Number.isSafeInteger(count) || count < 0 || count > MAX_RECOVERY_RESULT_COUNT)
    ) {
      throw new StorageError(`recovery ${name} count is invalid`);
    }
  }
  if (typeof result.imported === "number" && typeof result.total === "number" && result.imported > result.total) {
    throw new StorageError("recovery result counts are inconsistent");
  }
  return result as RecoveryResult;
}

const program = new Command();
program
  .name("telecrypt-io")
  .description("TeleCrypt.io CLI")
  .option("--json", "machine-readable JSON output")
  .showHelpAfterError()
  // Commander otherwise calls process.exit() for parse errors and writes its
  // own unredacted diagnostic/help text. Route all parse failures through the
  // same drained, JSON-aware boundary used by command actions below.
  .exitOverride()
  .configureOutput({ writeErr: () => {}, outputError: () => {} });

const storage = program
  .command("storage")
  .description("End-to-end encrypted file storage on Matrix");

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

storage
  .command("login")
  .description("Log in and persist the session + crypto store to the profile")
  .requiredOption("--homeserver <url>", "Matrix homeserver base URL")
  .option("--no-browser", "Do not open the verification page automatically")
  .action(async (opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      const session = await loginAndInitialize(opts.homeserver, {
        openBrowser: !opts.browser,
        onVerification: ({ verificationUri, verificationUriComplete, userCode }) => {
          // Progress output — stderr only, so it never corrupts the stdout
          // contract (--json's single JSON line / text mode's single line).
          process.stderr.write(
            [
              "",
              `To finish logging in, visit: ${safeOutputField(verificationUriComplete ?? verificationUri)}`,
              `and enter code: ${safeOutputField(userCode)}`,
              ...(opts.browser ? ["Attempting to open your browser…"] : []),
              "Waiting for approval…",
              "",
            ]
              .filter((l) => l !== "")
              .join("\n") + "\n",
          );
        },
      }, signal);
      return {
        json: { userId: session.userId, deviceId: session.deviceId, homeserver: session.homeserver },
        text: `Logged in as ${safeOutputField(session.userId)} (device ${safeOutputField(session.deviceId)})`,
      };
    });
  });

storage
  .command("whoami")
  .description("Print the current session identity")
  .action(async (_opts, command: Command) => {
    await runAction(command, async (_signal): Promise<CommandResult> => {
      const dir = profileDir();
      const lock = acquireProfileLock(dir);
      try {
        const session = readSession(dir, lock);
        if (!session) throw new StorageError("not logged in");
        const homeserver = assertTrustedHomeserver(session.homeserver);
        return {
          json: { userId: session.userId, deviceId: session.deviceId, homeserver },
          text: `${safeOutputField(session.userId)} (device ${safeOutputField(session.deviceId)}) @ ${safeOutputField(homeserver)}`,
        };
      } finally {
        lock.release();
      }
    });
  });

storage
  .command("logout")
  .description("Revoke the server session, then clear the local profile")
  .action(async (_opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      const result = await logoutProfile(profileDir(), signal);
      return {
        json: { loggedOut: true, serverLogout: result.serverLogout },
        text: result.hadSession ? "Logged out locally and on the server." : "Logged out locally.",
      };
    });
  });

// ---------------------------------------------------------------------------
// Recovery (Layer 2)
// ---------------------------------------------------------------------------

const recovery = storage.command("recovery").description("Server-side key backup / recovery");

recovery
  .command("setup")
  .description("Set up recovery (cross-signing + key backup) and print the Recovery Key")
  .action(async (_opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        markBackupWorkPending(opened.storage);
        const result = validateRecoveryResult(await withCoreDeadline(
          opened,
          (operationSignal) => core.setupRecovery(opened.storage, { signal: operationSignal }),
          "recovery setup",
        ));
        if (result.recoveryKey === undefined) throw new StorageError("recovery setup returned no recovery key");
        // Give any already-known megolm sessions a chance to actually reach
        // the server backup before this short-lived process exits — see
        // waitForBackupSettled's doc comment.
        await opened.run(
          (operationSignal) => waitForBackupSettled(opened.storage, undefined, operationSignal),
          "key backup settlement",
          25_000,
        );
        return {
          json: { ...result },
          text: [
            "Recovery Key (SAVE THIS — it is the only way to recover your files on a new device):",
            "",
            safeOutputField(result.recoveryKey),
          ].join("\n"),
        };
      });
    });
  });

recovery
  .command("restore")
  .description("Restore keys on this device from a Recovery Key (hidden prompt by default)")
  .option("--key-stdin", "Read the Recovery Key from stdin (for a pipe, never a TTY)")
  .action(async (opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      const recoveryKey = await readRecoveryKey(Boolean(opts.keyStdin), signal);
      return withProfileStorage(signal, async (opened) => {
          const result = validateRecoveryResult(await withCoreDeadline(
            opened,
            (operationSignal) => core.restoreRecovery(opened.storage, recoveryKey, { signal: operationSignal }),
            "recovery restore",
          ));
          if (result.imported === undefined || result.total === undefined) {
            throw new StorageError("recovery restore returned incomplete counts");
          }
          return {
            json: { ...result },
            text: `Restored ${safeOutputField(result.imported)}/${safeOutputField(result.total)} keys.`,
          };
        });
    });
  });

// ---------------------------------------------------------------------------
// Vaults
// ---------------------------------------------------------------------------

const vault = storage.command("vault").description("Shared vault operations");

vault
  .command("create <name>")
  .description("Create a new shared vault")
  .action(async (name: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const result = await withCoreDeadline(opened, (operationSignal) => core.createVault(opened.storage, name, { signal: operationSignal }), "vault creation");
        return {
          json: { ...result },
          text: `Created vault "${safeOutputField(result.name)}" (${safeOutputField(result.id)})`,
        };
      });
    });
  });

vault
  .command("list")
  .description("List vaults visible to the current user")
  .action(async (_opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const vaults = requireBoundedList(
          await withCoreDeadline(opened, (operationSignal) => core.listVaults(opened.storage, { signal: operationSignal }), "vault listing"),
          "vault listing",
        );
        return {
          json: { vaults },
          text:
            vaults.length === 0
              ? "(no vaults)"
              : vaults.map((f) => `${safeOutputField(f.id)}\t${safeOutputField(f.name)}`).join("\n"),
        };
      });
    });
  });

const subfolder = vault
  .command("subfolder")
  .description("Operations on folders within a shared vault");

subfolder
  .command("create <parentId> <name>")
  .description("Create a folder within a shared vault")
  .action(async (parentId: string, name: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const result = await withCoreDeadline(
          opened,
          (operationSignal) => core.createSubfolder(opened.storage, parentId, name, { signal: operationSignal }),
          "folder creation",
        );
        return {
          json: { ...result },
          text: `Created folder "${safeOutputField(result.name)}" (${safeOutputField(result.id)})`,
        };
      });
    });
  });

subfolder
  .command("list <parentId>")
  .description("List direct folders of a shared vault")
  .action(async (parentId: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const folders = requireBoundedList(
          await withCoreDeadline(opened, (operationSignal) => core.listSubfolders(opened.storage, parentId, { signal: operationSignal }), "folder listing"),
          "folder listing",
        );
        return {
          json: { folders },
          text:
            folders.length === 0
              ? "(no folders)"
              : folders.map((f) => `${safeOutputField(f.id)}\t${safeOutputField(f.name)}`).join("\n"),
        };
      });
    });
  });

subfolder
  .command("rename <folderId> <name>")
  .description("Rename a folder")
  .action(async (folderId: string, name: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const result = await withCoreDeadline(opened, (operationSignal) => core.renameFolder(opened.storage, folderId, name, { signal: operationSignal }), "folder rename");
        return { json: { ...result }, text: `Renamed folder ${safeOutputField(result.id)} to "${safeOutputField(result.name)}"` };
      });
    });
  });

subfolder
  .command("delete <folderId>")
  .description("Delete a folder")
  .action(async (folderId: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const result = await withCoreDeadline(opened, (operationSignal) => core.deleteFolder(opened.storage, folderId, { signal: operationSignal }), "folder deletion");
        return { json: { ...result }, text: `Deleted folder ${safeOutputField(result.id)}` };
      });
    });
  });

vault
  .command("join <vaultId>")
  .description("Accept a pending vault invitation (join the room)")
  .action(async (vaultId: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const result = await withCoreDeadline(opened, (operationSignal) => core.joinVault(opened.storage, vaultId, { signal: operationSignal }), "vault join");
        return { json: { ...result }, text: `Joined vault ${safeOutputField(result.vaultId)}` };
      });
    });
  });

vault
  .command("share <vaultId> <userId>")
  .description("Invite a participant to a shared vault at a given role")
  .option("--role <role>", "viewer or editor", "viewer")
  .action(async (vaultId: string, userId: string, opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      // Validate before opening storage so a bad --role fails fast. The core
      // operation repeats the check for callers outside this CLI.
      if (opts.role !== "viewer" && opts.role !== "editor") {
        throw new StorageError(`invalid --role "${safeOutputField(opts.role)}" (must be viewer or editor)`);
      }
      if (!isCanonicalMatrixUserId(userId)) throw new StorageError("shared member must be a canonical Matrix user ID");
      return withProfileStorage(signal, async (opened) => {
        const result = await withCoreDeadline(opened, (operationSignal) => core.shareVault(opened.storage, vaultId, userId, opts.role, { signal: operationSignal }), "vault share");
        return {
          json: { ...result },
          text: `Invited ${safeOutputField(result.userId)} to ${safeOutputField(result.vaultId)} as ${safeOutputField(result.role)}`,
        };
      });
    });
  });

vault
  .command("members <vaultId>")
  .description("List participants and their roles")
  .action(async (vaultId: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const members = requireBoundedList(
          await withCoreDeadline(opened, (operationSignal) => core.listMembers(opened.storage, vaultId, { signal: operationSignal }), "member listing"),
          "member listing",
        );
        return {
          json: { members },
          text: members.map((m) => `${safeOutputField(m.userId)}\t${safeOutputField(m.role)}\t${safeOutputField(m.membership)}`).join("\n"),
        };
      });
    });
  });

vault
  .command("unshare <vaultId> <userId>")
  .description("Remove a participant from a shared vault")
  .action(async (vaultId: string, userId: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      if (!isCanonicalMatrixUserId(userId)) throw new StorageError("shared member must be a canonical Matrix user ID");
      return withProfileStorage(signal, async (opened) => {
        const result = await withCoreDeadline(opened, (operationSignal) => core.unshareVault(opened.storage, vaultId, userId, { signal: operationSignal }), "vault unshare");
        return { json: { ...result }, text: `Removed ${safeOutputField(result.userId)} from ${safeOutputField(result.vaultId)}` };
      });
    });
  });

vault
  .command("rename <vaultId> <name>")
  .description("Rename a vault")
  .action(async (vaultId: string, name: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const result = await withCoreDeadline(opened, (operationSignal) => core.renameVault(opened.storage, vaultId, name, { signal: operationSignal }), "vault rename");
        return { json: { ...result }, text: `Renamed vault ${safeOutputField(result.id)} to "${safeOutputField(result.name)}"` };
      });
    });
  });

vault
  .command("delete <vaultId>")
  .description("Delete a vault")
  .action(async (vaultId: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const result = await withCoreDeadline(opened, (operationSignal) => core.deleteVault(opened.storage, vaultId, { signal: operationSignal }), "vault deletion");
        return { json: { ...result }, text: `Deleted vault ${safeOutputField(result.id)}` };
      });
    });
  });

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

const file = storage.command("file").description("File operations within a vault or folder");

file
  .command("upload <treeId> <path>")
  .description("Encrypt and upload a local file into a vault or folder")
  .option("--name <name>", "Name to store the file as (default: basename of path)")
  .action(async (treeId: string, filePath: string, opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      const data = readBoundedInput(filePath);
      return withProfileStorage(signal, async (opened) => {
        markBackupWorkPending(opened.storage);
        const name = opts.name ?? path.basename(filePath);
        const result = await opened.run(
          (operationSignal) => core.uploadFile(
            opened.storage,
            treeId,
            name,
            data,
            guessMimetype(filePath),
            { signal: operationSignal },
          ),
          "file upload",
        );
        // If recovery/backup is already active for this account, give the
        // new session's key a chance to actually reach the server backup
        // before this short-lived process exits.
        await opened.run(
          (operationSignal) => waitForBackupSettled(opened.storage, undefined, operationSignal),
          "key backup settlement",
          25_000,
        );
        return {
          json: { ...result },
          text: `Uploaded "${safeOutputField(result.name)}" as ${safeOutputField(result.id)}`,
        };
      });
    });
  });

file
  .command("list <treeId>")
  .description("List files in a vault or folder")
  .action(async (treeId: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const files = requireBoundedList(
          await withCoreDeadline(opened, (operationSignal) => core.listFiles(opened.storage, treeId, { signal: operationSignal }), "file listing"),
          "file listing",
        );
        return {
          json: { files },
          text: files.length === 0 ? "(no files)" : files.map((f) => `${safeOutputField(f.id)}\t${safeOutputField(f.name)}`).join("\n"),
        };
      });
    });
  });

file
  .command("download <treeId> <fileId> <destPath>")
  .description("Download and decrypt a file to a local path")
  .action(async (treeId: string, fileId: string, destPath: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        // The SDK returns a complete Uint8Array and enforces its 128 MiB media
        // bound internally. Keep the CLI's outer deadline and destination
        // checks around that API until a streaming surface is available.
        const result = await opened.run(
          (operationSignal) => core.downloadFile(opened.storage, treeId, fileId, { signal: operationSignal }),
          "file download",
        );
        writeBoundedDownload(destPath, result.bytes);
        return {
          json: { path: destPath, bytes: result.bytes.byteLength, mimetype: result.mimetype },
          text: `Downloaded ${result.bytes.byteLength} bytes to ${safeOutputField(destPath)}`,
        };
      });
    });
  });

file
  .command("rename <treeId> <fileId> <name>")
  .description("Rename a file")
  .action(async (treeId: string, fileId: string, name: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const result = await withCoreDeadline(opened, (operationSignal) => core.renameFile(opened.storage, treeId, fileId, name, { signal: operationSignal }), "file rename");
        return { json: { ...result }, text: `Renamed file ${safeOutputField(result.id)} to "${safeOutputField(result.name)}"` };
      });
    });
  });

file
  .command("delete <treeId> <fileId>")
  .description("Delete a file")
  .action(async (treeId: string, fileId: string, _opts, command: Command) => {
    await runAction(command, async (signal): Promise<CommandResult> => {
      return withProfileStorage(signal, async (opened) => {
        const result = await withCoreDeadline(opened, (operationSignal) => core.deleteFile(opened.storage, treeId, fileId, { signal: operationSignal }), "file deletion");
        return { json: { ...result }, text: `Deleted file ${safeOutputField(result.id)}` };
      });
    });
  });

// ---------------------------------------------------------------------------

async function writeParseError(line: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => {
      process.stderr.off("error", onError);
      reject(error);
    };
    process.stderr.once("error", onError);
    process.stderr.write(`${line}\n`, () => {
      process.stderr.off("error", onError);
      resolve();
    });
  });
}

export async function main(argv: string[] = process.argv): Promise<void> {
  const removeCancellationHandlers = installCancellationHandlers();
  try {
    await program.parseAsync(argv);
  } catch (err) {
    const commanderCode =
      err && typeof err === "object" && "code" in err && typeof err.code === "string" ? err.code : undefined;
    if (commanderCode === "commander.helpDisplayed" || commanderCode === "commander.version") {
      process.exitCode = cancellationExitCode() ?? 0;
      return;
    }
    const message = safeErrorMessage(err instanceof Error ? err.message : String(err));
    const jsonMode = argv.includes("--json");
    try {
      await writeParseError(jsonMode ? JSON.stringify({ error: message }) : `Error: ${message}`);
    } catch {
      // There is no reliable fallback if stderr itself has failed; retain the
      // non-zero status without creating an unhandled rejection.
    } finally {
      process.exitCode = cancellationExitCode() ?? 1;
    }
  } finally {
    removeCancellationHandlers();
    scheduleBoundedNormalExit(typeof process.exitCode === "number" ? process.exitCode : 0);
  }
}

function isDirectInvocation(): boolean {
  if (!process.argv[1]) return false;
  try {
    return pathToFileURL(realpathSync(process.argv[1])).href === import.meta.url;
  } catch {
    return false;
  }
}

if (isDirectInvocation()) void main();
