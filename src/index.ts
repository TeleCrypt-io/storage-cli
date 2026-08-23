#!/usr/bin/env node
import "fake-indexeddb/auto";
import * as fs from "node:fs";
import * as path from "node:path";
import { Command } from "commander";
import { clearProfile, readSession, writeSession } from "./profile.js";
import { initStorageForNewSession, openStorage, waitForBackupSettled } from "./storage.js";
import { runAction, CommandResult } from "./output.js";
import { StorageError } from "@telecrypt-io/storage/core";
import * as core from "@telecrypt-io/storage/core";
import { runDeviceCodeLogin } from "./oidc.js";

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
// output.ts), never console.*, so this can't swallow anything we emit
// ourselves. Set TELECRYPT_IO_STORAGE_DEBUG=1 to see the SDK's logs again
// (all routed to stderr, labelled) when troubleshooting.
if (!process.env.TELECRYPT_IO_STORAGE_DEBUG) {
  console.log = () => {};
  console.debug = () => {};
  console.info = () => {};
  console.trace = () => {};
  console.warn = () => {};
  console.error = () => {};
} else {
  const toStderr =
    (label: string) =>
    (...args: unknown[]) =>
      process.stderr.write(`[${label}] ${args.map(String).join(" ")}\n`);
  console.log = toStderr("log");
  console.debug = toStderr("debug");
  console.info = toStderr("info");
  console.trace = toStderr("trace");
  console.warn = toStderr("warn");
  console.error = toStderr("error");
}

const EXT_MIMETYPES: Record<string, string> = {
  ".txt": "text/plain",
  ".json": "application/json",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".pdf": "application/pdf",
  ".md": "text/markdown",
};
const MAX_RECOVERY_KEY_BYTES = 16 * 1024;

function guessMimetype(filePath: string): string {
  return EXT_MIMETYPES[path.extname(filePath).toLowerCase()] ?? "application/octet-stream";
}

function requireRecoveryKey(value: string): string {
  const recoveryKey = value.replace(/[\r\n]+$/, "");
  if (!recoveryKey) throw new StorageError("recovery key was empty");
  return recoveryKey;
}

/** Reads a piped recovery key only when the caller selected that explicit
 * non-interactive interface. Keeping this separate from the command line
 * prevents a recovery key being retained in shell history or process lists. */
async function readRecoveryKeyFromStdin(): Promise<string> {
  if (process.stdin.isTTY) {
    throw new StorageError("--key-stdin requires a piped recovery key; omit it for the hidden prompt");
  }

  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    const data = Buffer.from(chunk);
    length += data.length;
    if (length > MAX_RECOVERY_KEY_BYTES) throw new StorageError("recovery key input is unexpectedly large");
    chunks.push(data);
  }
  return requireRecoveryKey(Buffer.concat(chunks).toString("utf8"));
}

/** Prompts on a TTY without echoing the recovery key. */
async function promptForRecoveryKey(): Promise<string> {
  if (!process.stdin.isTTY || typeof process.stdin.setRawMode !== "function") {
    throw new StorageError("recovery key requires a TTY prompt or explicit --key-stdin input");
  }

  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    const chars: string[] = [];
    let byteLength = 0;
    let rawModeEnabled = false;
    let settled = false;

    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      stdin.off("data", onData);
      let restoreError: unknown;
      try {
        if (rawModeEnabled || stdin.isRaw) stdin.setRawMode(wasRaw ?? false);
      } catch (err) {
        restoreError = err;
      } finally {
        stdin.pause();
      }
      process.stderr.write("\n");
      if (error) reject(error);
      else if (restoreError) reject(restoreError);
      else {
        try {
          resolve(requireRecoveryKey(chars.join("")));
        } catch (err) {
          reject(err);
        }
      }
    };
    const onData = (data: Buffer | string) => {
      for (const char of data.toString()) {
        if (char === "\r" || char === "\n") {
          finish();
          return;
        }
        if (char === "\u0003") {
          finish(new StorageError("recovery key input interrupted"));
          return;
        }
        if (char === "\b" || char === "\u007f") {
          const removed = chars.pop();
          if (removed) byteLength -= Buffer.byteLength(removed, "utf8");
          continue;
        }
        byteLength += Buffer.byteLength(char, "utf8");
        if (byteLength > MAX_RECOVERY_KEY_BYTES) {
          finish(new StorageError("recovery key input is unexpectedly large"));
          return;
        }
        chars.push(char);
      }
    };

    try {
      process.stderr.write("Recovery Key: ");
      stdin.setRawMode(true);
      rawModeEnabled = true;
      stdin.resume();
      stdin.on("data", onData);
    } catch (err) {
      finish(err as Error);
    }
  });
}

async function readRecoveryKey(useStdin: boolean): Promise<string> {
  return useStdin ? readRecoveryKeyFromStdin() : promptForRecoveryKey();
}

const program = new Command();
program
  .name("telecrypt-io")
  .description("TeleCrypt.io CLI")
  .option("--json", "machine-readable JSON output")
  .showHelpAfterError();

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
  .action(async (opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const session = await runDeviceCodeLogin(opts.homeserver, {
        onVerification: ({ verificationUri, verificationUriComplete, userCode }) => {
          // Progress output — stderr only, so it never corrupts the stdout
          // contract (--json's single JSON line / text mode's single line).
          process.stderr.write(
            [
              "",
              `To finish logging in, visit: ${verificationUriComplete ?? verificationUri}`,
              `and enter code: ${userCode}`,
              "Attempting to open your browser…",
              "Waiting for approval…",
              "",
            ]
              .filter((l) => l !== "")
              .join("\n") + "\n",
          );
        },
      });

      writeSession(session);
      // Establishes this device's crypto identity and does a first sync
      // (proves connectivity end-to-end), and writes the initial crypto
      // store snapshot so later commands have something to load.
      const opened = await initStorageForNewSession(session);
      await opened.close();
      return {
        json: { userId: session.userId, deviceId: session.deviceId, homeserver: session.homeserver },
        text: `Logged in as ${session.userId} (device ${session.deviceId})`,
      };
    });
  });

storage
  .command("whoami")
  .description("Print the current session identity")
  .action(async (_opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const session = readSession();
      if (!session) throw new StorageError("not logged in");
      return {
        json: { userId: session.userId, deviceId: session.deviceId, homeserver: session.homeserver },
        text: `${session.userId} (device ${session.deviceId}) @ ${session.homeserver}`,
      };
    });
  });

storage
  .command("logout")
  .description("Clear the local profile (session + crypto store)")
  .action(async (_opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const session = readSession();
      if (session) {
        // Best-effort server-side logout; local profile is cleared either way.
        await fetch(`${session.homeserver}/_matrix/client/v3/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${session.accessToken}` },
        }).catch(() => undefined);
      }
      clearProfile();
      return { json: { loggedOut: true }, text: "Logged out." };
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
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.setupRecovery(opened.storage);
        // Give any already-known megolm sessions a chance to actually reach
        // the server backup before this short-lived process exits — see
        // waitForBackupSettled's doc comment.
        await waitForBackupSettled(opened.storage);
        return {
          json: { ...result },
          text: [
            "Recovery Key (SAVE THIS — it is the only way to recover your files on a new device):",
            "",
            result.recoveryKey,
          ].join("\n"),
        };
      } finally {
        await opened.close();
      }
    });
  });

recovery
  .command("restore")
  .description("Restore keys on this device from a Recovery Key (hidden prompt by default)")
  .option("--key-stdin", "Read the Recovery Key from stdin (for a pipe, never a TTY)")
  .action(async (opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const recoveryKey = await readRecoveryKey(Boolean(opts.keyStdin));
      const opened = await openStorage();
      try {
        const result = await core.restoreRecovery(opened.storage, recoveryKey);
        return {
          json: { ...result },
          text: `Restored ${result.imported}/${result.total} keys.`,
        };
      } finally {
        await opened.close();
      }
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
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.createVault(opened.storage, name);
        return {
          json: { ...result },
          text: `Created vault "${result.name}" (${result.id})`,
        };
      } finally {
        await opened.close();
      }
    });
  });

vault
  .command("list")
  .description("List vaults visible to the current user")
  .action(async (_opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const vaults = await core.listVaults(opened.storage);
        return {
          json: { vaults },
          text:
            vaults.length === 0
              ? "(no vaults)"
              : vaults.map((f) => `${f.id}\t${f.name}`).join("\n"),
        };
      } finally {
        await opened.close();
      }
    });
  });

const subfolder = vault
  .command("subfolder")
  .description("Operations on folders within a shared vault");

subfolder
  .command("create <parentId> <name>")
  .description("Create a folder within a shared vault")
  .action(async (parentId: string, name: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.createSubfolder(opened.storage, parentId, name);
        return {
          json: { ...result },
          text: `Created folder "${result.name}" (${result.id})`,
        };
      } finally {
        await opened.close();
      }
    });
  });

subfolder
  .command("list <parentId>")
  .description("List direct folders of a shared vault")
  .action(async (parentId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const folders = await core.listSubfolders(opened.storage, parentId);
        return {
          json: { folders },
          text:
            folders.length === 0
              ? "(no folders)"
              : folders.map((f) => `${f.id}\t${f.name}`).join("\n"),
        };
      } finally {
        await opened.close();
      }
    });
  });

subfolder
  .command("rename <folderId> <name>")
  .description("Rename a folder")
  .action(async (folderId: string, name: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.renameFolder(opened.storage, folderId, name);
        return { json: { ...result }, text: `Renamed folder ${result.id} to "${result.name}"` };
      } finally {
        await opened.close();
      }
    });
  });

subfolder
  .command("delete <folderId>")
  .description("Delete a folder")
  .action(async (folderId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.deleteFolder(opened.storage, folderId);
        return { json: { ...result }, text: `Deleted folder ${result.id}` };
      } finally {
        await opened.close();
      }
    });
  });

vault
  .command("join <vaultId>")
  .description("Accept a pending vault invitation (join the room)")
  .action(async (vaultId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.joinVault(opened.storage, vaultId);
        return { json: { ...result }, text: `Joined vault ${result.vaultId}` };
      } finally {
        await opened.close();
      }
    });
  });

vault
  .command("share <vaultId> <userId>")
  .description("Invite a participant to a shared vault at a given role")
  .option("--role <role>", "viewer or editor", "viewer")
  .action(async (vaultId: string, userId: string, opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      // Validate before opening storage so a bad --role fails fast. The core
      // operation repeats the check for callers outside this CLI.
      if (opts.role !== "viewer" && opts.role !== "editor") {
        throw new StorageError(`invalid --role "${opts.role}" (must be viewer or editor)`);
      }
      const opened = await openStorage();
      try {
        const result = await core.shareVault(opened.storage, vaultId, userId, opts.role);
        return {
          json: { ...result },
          text: `Invited ${result.userId} to ${result.vaultId} as ${result.role}`,
        };
      } finally {
        await opened.close();
      }
    });
  });

vault
  .command("members <vaultId>")
  .description("List participants and their roles")
  .action(async (vaultId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const members = await core.listMembers(opened.storage, vaultId);
        return {
          json: { members },
          text: members.map((m) => `${m.userId}\t${m.role}\t${m.membership}`).join("\n"),
        };
      } finally {
        await opened.close();
      }
    });
  });

vault
  .command("unshare <vaultId> <userId>")
  .description("Remove a participant from a shared vault")
  .action(async (vaultId: string, userId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.unshareVault(opened.storage, vaultId, userId);
        return { json: { ...result }, text: `Removed ${result.userId} from ${result.vaultId}` };
      } finally {
        await opened.close();
      }
    });
  });

vault
  .command("rename <vaultId> <name>")
  .description("Rename a vault")
  .action(async (vaultId: string, name: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.renameVault(opened.storage, vaultId, name);
        return { json: { ...result }, text: `Renamed vault ${result.id} to "${result.name}"` };
      } finally {
        await opened.close();
      }
    });
  });

vault
  .command("delete <vaultId>")
  .description("Delete a vault")
  .action(async (vaultId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.deleteVault(opened.storage, vaultId);
        return { json: { ...result }, text: `Deleted vault ${result.id}` };
      } finally {
        await opened.close();
      }
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
    await runAction(command, async (): Promise<CommandResult> => {
      if (!fs.existsSync(filePath)) {
        throw new StorageError(`file not found: ${filePath}`);
      }
      const opened = await openStorage();
      try {
        const name = opts.name ?? path.basename(filePath);
        const data = fs.readFileSync(filePath);
        const result = await core.uploadFile(
          opened.storage,
          treeId,
          name,
          data,
          guessMimetype(filePath),
        );
        // If recovery/backup is already active for this account, give the
        // new session's key a chance to actually reach the server backup
        // before this short-lived process exits.
        await waitForBackupSettled(opened.storage);
        return {
          json: { ...result },
          text: `Uploaded "${result.name}" as ${result.id}`,
        };
      } finally {
        await opened.close();
      }
    });
  });

file
  .command("list <treeId>")
  .description("List files in a vault or folder")
  .action(async (treeId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const files = await core.listFiles(opened.storage, treeId);
        return {
          json: { files },
          text: files.length === 0 ? "(no files)" : files.map((f) => `${f.id}\t${f.name}`).join("\n"),
        };
      } finally {
        await opened.close();
      }
    });
  });

file
  .command("download <treeId> <fileId> <destPath>")
  .description("Download and decrypt a file to a local path")
  .action(async (treeId: string, fileId: string, destPath: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.downloadFile(opened.storage, treeId, fileId);
        fs.writeFileSync(destPath, Buffer.from(result.bytes));
        return {
          json: { path: destPath, bytes: result.bytes.byteLength, mimetype: result.mimetype },
          text: `Downloaded ${result.bytes.byteLength} bytes to ${destPath}`,
        };
      } finally {
        await opened.close();
      }
    });
  });

file
  .command("rename <treeId> <fileId> <name>")
  .description("Rename a file")
  .action(async (treeId: string, fileId: string, name: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.renameFile(opened.storage, treeId, fileId, name);
        return { json: { ...result }, text: `Renamed file ${result.id} to "${result.name}"` };
      } finally {
        await opened.close();
      }
    });
  });

file
  .command("delete <treeId> <fileId>")
  .description("Delete a file")
  .action(async (treeId: string, fileId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.deleteFile(opened.storage, treeId, fileId);
        return { json: { ...result }, text: `Deleted file ${result.id}` };
      } finally {
        await opened.close();
      }
    });
  });

// ---------------------------------------------------------------------------

program
  .parseAsync(process.argv)
  .catch((err) => {
    process.stderr.write(`Error: ${(err as Error).message}\n`);
    process.exitCode = 1;
  })
  .finally(() => {
    // Every action closes its own storage (stopClient()), but Node's global
    // fetch (undici) can keep a keep-alive socket open past that, leaving
    // the process hanging instead of exiting on its own. Exit explicitly
    // once the command has fully finished and printed its output.
    process.exit(process.exitCode ?? 0);
  });
