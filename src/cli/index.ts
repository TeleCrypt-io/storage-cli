#!/usr/bin/env node
import "fake-indexeddb/auto";
import * as fs from "node:fs";
import * as path from "node:path";
import { Command } from "commander";
import { createClient } from "matrix-js-sdk";
import { clearProfile, readSession, writeSession, Session } from "./profile.js";
import { initStorageForNewSession, openStorage, waitForBackupSettled } from "./storage.js";
import { CliError } from "./errors.js";
import { runAction, CommandResult } from "./output.js";
import * as core from "../core/operations.js";

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

function guessMimetype(filePath: string): string {
  return EXT_MIMETYPES[path.extname(filePath).toLowerCase()] ?? "application/octet-stream";
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
  .requiredOption("--user <localpart>", "Username (localpart or full MXID)")
  .requiredOption("--password <pw>", "Password")
  .action(async (opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const client = createClient({ baseUrl: opts.homeserver });
      let res;
      try {
        res = await client.loginWithPassword(opts.user, opts.password);
      } catch (err) {
        throw new CliError(`login failed: ${(err as Error).message}`);
      }
      const session: Session = {
        homeserver: opts.homeserver,
        userId: res.user_id,
        deviceId: res.device_id,
        accessToken: res.access_token,
      };
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
  .command("register")
  .description("Register a new account (dev/test convenience), then log in")
  .requiredOption("--homeserver <url>", "Matrix homeserver base URL")
  .requiredOption("--user <localpart>", "Username (localpart)")
  .requiredOption("--password <pw>", "Password")
  .action(async (opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const res = await fetch(`${opts.homeserver}/_matrix/client/v3/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: opts.user,
          password: opts.password,
          auth: { type: "m.login.dummy" },
          inhibit_login: false,
        }),
      });
      if (!res.ok) {
        const body = await res.text();
        throw new CliError(`registration failed (${res.status}): ${body}`);
      }
      const data = (await res.json()) as {
        user_id: string;
        access_token: string;
        device_id: string;
      };
      const session: Session = {
        homeserver: opts.homeserver,
        userId: data.user_id,
        deviceId: data.device_id,
        accessToken: data.access_token,
      };
      writeSession(session);
      const opened = await initStorageForNewSession(session);
      await opened.close();
      return {
        json: { userId: session.userId, deviceId: session.deviceId, homeserver: session.homeserver },
        text: `Registered and logged in as ${session.userId} (device ${session.deviceId})`,
      };
    });
  });

storage
  .command("whoami")
  .description("Print the current session identity")
  .action(async (_opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const session = readSession();
      if (!session) throw new CliError("not logged in");
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
  .command("restore <recoveryKey>")
  .description("Restore keys on this device from a Recovery Key")
  .action(async (recoveryKey: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
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
// Folders
// ---------------------------------------------------------------------------

const folder = storage.command("folder").description("Shared folder operations");

folder
  .command("create <name>")
  .description("Create a new shared folder")
  .action(async (name: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.createFolder(opened.storage, name);
        return {
          json: { folderId: result.id, name: result.name },
          text: `Created folder "${result.name}" (${result.id})`,
        };
      } finally {
        await opened.close();
      }
    });
  });

folder
  .command("list")
  .description("List folders visible to the current user")
  .action(async (_opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const folders = await core.listFolders(opened.storage);
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

folder
  .command("join <folderId>")
  .description("Accept a pending folder invitation (join the room)")
  .action(async (folderId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.joinFolder(opened.storage, folderId);
        return { json: { ...result }, text: `Joined folder ${result.folderId}` };
      } finally {
        await opened.close();
      }
    });
  });

folder
  .command("share <folderId> <userId>")
  .description("Invite a participant to a shared folder at a given role")
  .option("--role <role>", "viewer or editor", "viewer")
  .action(async (folderId: string, userId: string, opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      // Validated here too (before openStorage/login is even attempted) so
      // a bad --role fails fast exactly as before; core.shareFolder repeats
      // the same check so it's still safe to call standalone (e.g. from a
      // future UI) without this CLI-side pre-check.
      if (opts.role !== "viewer" && opts.role !== "editor") {
        throw new CliError(`invalid --role "${opts.role}" (must be viewer or editor)`);
      }
      const opened = await openStorage();
      try {
        const result = await core.shareFolder(opened.storage, folderId, userId, opts.role);
        return {
          json: { ...result },
          text: `Invited ${result.userId} to ${result.folderId} as ${result.role}`,
        };
      } finally {
        await opened.close();
      }
    });
  });

folder
  .command("members <folderId>")
  .description("List participants and their roles")
  .action(async (folderId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const members = await core.listMembers(opened.storage, folderId);
        return {
          json: { members },
          text: members.map((m) => `${m.userId}\t${m.role}\t${m.membership}`).join("\n"),
        };
      } finally {
        await opened.close();
      }
    });
  });

folder
  .command("unshare <folderId> <userId>")
  .description("Remove a participant from a shared folder")
  .action(async (folderId: string, userId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.unshareFolder(opened.storage, folderId, userId);
        return { json: { ...result }, text: `Removed ${result.userId} from ${result.folderId}` };
      } finally {
        await opened.close();
      }
    });
  });

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

const file = storage.command("file").description("File operations within a folder");

file
  .command("upload <folderId> <path>")
  .description("Encrypt and upload a local file into a folder")
  .option("--name <name>", "Name to store the file as (default: basename of path)")
  .action(async (folderId: string, filePath: string, opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      if (!fs.existsSync(filePath)) {
        throw new CliError(`file not found: ${filePath}`);
      }
      const opened = await openStorage();
      try {
        const name = opts.name ?? path.basename(filePath);
        const data = fs.readFileSync(filePath);
        const result = await core.uploadFile(
          opened.storage,
          folderId,
          name,
          data,
          guessMimetype(filePath),
        );
        // If recovery/backup is already active for this account, give the
        // new session's key a chance to actually reach the server backup
        // before this short-lived process exits.
        await waitForBackupSettled(opened.storage);
        return {
          json: { fileId: result.id, name: result.name },
          text: `Uploaded "${result.name}" as ${result.id}`,
        };
      } finally {
        await opened.close();
      }
    });
  });

file
  .command("list <folderId>")
  .description("List files in a folder")
  .action(async (folderId: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const files = await core.listFiles(opened.storage, folderId);
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
  .command("download <folderId> <fileId> <destPath>")
  .description("Download and decrypt a file to a local path")
  .action(async (folderId: string, fileId: string, destPath: string, _opts, command: Command) => {
    await runAction(command, async (): Promise<CommandResult> => {
      const opened = await openStorage();
      try {
        const result = await core.downloadFile(opened.storage, folderId, fileId);
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
