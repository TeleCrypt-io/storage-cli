#!/usr/bin/env node
import "fake-indexeddb/auto";
import { Console } from "node:console";
import { realpathSync } from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { Command } from "commander";
import {
  acquireProfileLock,
  isCanonicalMatrixUserId,
  profileDir,
  readSession,
  throwWithLockReleaseFailure,
} from "./profile.js";
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
import { readBoundedInput, writeDownload } from "./fileTransfer.js";
import { readRecoveryKey } from "./recoveryInput.js";

// matrix-js-sdk and rust-crypto use the process-global console. Keep their
// complete diagnostics off stdout, where the CLI's successful machine output
// is written, while preserving them on stderr for investigation. The CLI's
// own result/error writer uses the streams directly (see output.ts).
const diagnosticConsole = new Console({ stdout: process.stderr, stderr: process.stderr, ignoreErrors: false });
console.log = diagnosticConsole.log.bind(diagnosticConsole);
console.debug = diagnosticConsole.debug.bind(diagnosticConsole);
console.info = diagnosticConsole.info.bind(diagnosticConsole);
console.trace = diagnosticConsole.trace.bind(diagnosticConsole);
console.warn = diagnosticConsole.warn.bind(diagnosticConsole);
console.error = diagnosticConsole.error.bind(diagnosticConsole);

const EXT_MIMETYPES: Record<string, string> = {
  ".txt": "text/plain",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".pdf": "application/pdf",
  ".md": "text/markdown",
};
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
  let operationFailed = false;
  let operationError: unknown;
  try {
    return await operation(opened);
  } catch (error) {
    operationFailed = true;
    operationError = error;
    throw error;
  } finally {
    try {
      await opened.close();
    } catch (closeError) {
      if (operationFailed) {
        throw new AggregateError(
          [operationError, closeError],
          "storage operation and cleanup failed",
        );
      }
      throw closeError;
    }
  }
}

function guessMimetype(filePath: string): string {
  return EXT_MIMETYPES[path.extname(filePath).toLowerCase()] ?? "application/octet-stream";
}

function writeCommanderDiagnostic(value: string): void {
  process.stderr.write(value.split(/\r?\n/u).map((line) => safeErrorMessage(line)).join("\n"));
}

const program = new Command();
program
  .name("telecrypt-io")
  .description("TeleCrypt.io CLI")
  .option("--json", "machine-readable JSON output")
  .showHelpAfterError()
  // Commander otherwise calls process.exit() for parse errors. Keep its
  // sanitized diagnostics visible on stderr and route the final status through
  // main().
  .exitOverride()
  .configureOutput({
    writeErr: writeCommanderDiagnostic,
    outputError: (message, write) => write(message),
  });

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
      let operationFailed = false;
      let operationError: unknown;
      try {
        const session = readSession(dir, lock);
        if (!session) throw new StorageError("not logged in");
        const homeserver = assertTrustedHomeserver(session.homeserver);
        return {
          json: { userId: session.userId, deviceId: session.deviceId, homeserver },
          text: `${safeOutputField(session.userId)} (device ${safeOutputField(session.deviceId)}) @ ${safeOutputField(homeserver)}`,
        };
      } catch (error) {
        operationFailed = true;
        operationError = error;
        throw error;
      } finally {
        if (operationFailed) throwWithLockReleaseFailure(lock, operationError);
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
        const result = await withCoreDeadline(
          opened,
          (operationSignal) => core.setupRecovery(opened.storage, { signal: operationSignal }),
          "recovery setup",
        );
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
          const result = await withCoreDeadline(
            opened,
            (operationSignal) => core.restoreRecovery(opened.storage, recoveryKey, { signal: operationSignal }),
            "recovery restore",
          );
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
        const vaults = await withCoreDeadline(
          opened,
          (operationSignal) => core.listVaults(opened.storage, { signal: operationSignal }),
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
        const folders = await withCoreDeadline(
          opened,
          (operationSignal) => core.listSubfolders(opened.storage, parentId, { signal: operationSignal }),
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
        const members = await withCoreDeadline(
          opened,
          (operationSignal) => core.listMembers(opened.storage, vaultId, { signal: operationSignal }),
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
        const files = await withCoreDeadline(
          opened,
          (operationSignal) => core.listFiles(opened.storage, treeId, { signal: operationSignal }),
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
        // The SDK returns a complete Uint8Array. Keep the CLI's outer deadline
        // and destination checks around that API.
        const result = await opened.run(
          (operationSignal) => core.downloadFile(opened.storage, treeId, fileId, { signal: operationSignal }),
          "file download",
        );
        writeDownload(destPath, result.bytes);
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
    const message = safeErrorMessage(err);
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
