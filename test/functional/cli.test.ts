import { describe, it, expect } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import { cliJson, freshProfileDir, runCli } from "../harness/cli";
import { waitFor } from "../harness/waitFor";

const HOMESERVER = "http://localhost:8008";

function randomUser(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 8)}`;
}

/** Registers a brand-new account in the given profile dir and returns its
 * userId + the password (needed later for a fresh-device login in CLI.4). */
async function registerProfile(
  dir: string,
  prefix: string,
): Promise<{ userId: string; username: string; password: string }> {
  const username = randomUser(prefix);
  const password = "pw_" + Math.random().toString(36).slice(2, 10);
  const res = await cliJson(
    ["register", "--homeserver", HOMESERVER, "--user", username, "--password", password],
    { SECURE_STORAGE_HOME: dir },
  );
  expect(res.code).toBe(0);
  return { userId: res.json.userId as string, username, password };
}

describe("CLI", () => {
  it(
    "CLI.1 cross-process persistence: upload in one process, download in a separate one, byte-identical",
    async () => {
      const dir = freshProfileDir("persist");
      const env = { SECURE_STORAGE_HOME: dir };

      // Every step below is its OWN subprocess — this is the mandatory proof
      // that the Matrix session + megolm keys survive across process exits.
      await registerProfile(dir, "persist");

      const recoverySetup = await cliJson(["recovery", "setup"], env);
      expect(recoverySetup.code).toBe(0);
      expect(typeof recoverySetup.json.recoveryKey).toBe("string");

      const folderRes = await cliJson(["folder", "create", "PersistFolder"], env);
      expect(folderRes.code).toBe(0);
      const folderId = folderRes.json.folderId as string;
      expect(folderId).toBeTruthy();

      const srcPath = path.join(dir, "source.txt");
      const originalBytes = `cross-process proof ${Math.random()}`;
      fs.writeFileSync(srcPath, originalBytes);

      const uploadRes = await cliJson(["file", "upload", folderId, srcPath], env);
      expect(uploadRes.code).toBe(0);
      const fileId = uploadRes.json.fileId as string;
      expect(fileId).toBeTruthy();

      // A completely fresh process, no state shared except the profile dir on
      // disk: this is the actual proof. If crypto persistence failed, this
      // would throw a decryption error (empty megolm store).
      const destPath = path.join(dir, "downloaded.txt");
      const downloadRes = await cliJson(
        ["file", "download", folderId, fileId, destPath],
        env,
      );
      expect(downloadRes.code).toBe(0);

      const downloadedBytes = fs.readFileSync(destPath, "utf8");
      expect(downloadedBytes).toBe(originalBytes);
    },
    60000,
  );

  it(
    "CLI.2 multi-participant shared folder: B uploads, A downloads B's file byte-identical; uninvited C cannot list it",
    async () => {
      const dirA = freshProfileDir("multiA");
      const dirB = freshProfileDir("multiB");
      const dirC = freshProfileDir("multiC");
      const envA = { SECURE_STORAGE_HOME: dirA };
      const envB = { SECURE_STORAGE_HOME: dirB };
      const envC = { SECURE_STORAGE_HOME: dirC };

      await registerProfile(dirA, "multiA");
      const userB = await registerProfile(dirB, "multiB");
      await registerProfile(dirC, "multiC");

      const folderRes = await cliJson(["folder", "create", "Shared"], envA);
      expect(folderRes.code).toBe(0);
      const folderId = folderRes.json.folderId as string;

      const shareRes = await cliJson(
        ["folder", "share", folderId, userB.userId, "--role", "editor"],
        envA,
      );
      expect(shareRes.code).toBe(0);
      expect(shareRes.json).toMatchObject({ folderId, userId: userB.userId, role: "editor" });

      const joinRes = await cliJson(["folder", "join", folderId], envB);
      expect(joinRes.code).toBe(0);

      const srcPath = path.join(dirB, "from-b.txt");
      const originalBytes = `B's file ${Math.random()}`;
      fs.writeFileSync(srcPath, originalBytes);

      const uploadRes = await cliJson(["file", "upload", folderId, srcPath], envB);
      expect(uploadRes.code).toBe(0);
      const fileId = uploadRes.json.fileId as string;

      // A downloads B's file. The megolm key-share to-device message is
      // awaited as part of B's upload resolving, so this should generally
      // succeed on the first try — but poll the real condition (repeated
      // fresh CLI invocations, each a genuine independent sync) rather than
      // assume, since key delivery is still asynchronous end-to-end.
      const destPath = path.join(dirA, "from-b-downloaded.txt");
      const downloadResult = await waitFor(
        async () => {
          const res = await cliJson(["file", "download", folderId, fileId, destPath], envA);
          return res.code === 0 ? res : null;
        },
        { label: "A decrypts B's file", timeoutMs: 30000, intervalMs: 1500 },
      );
      expect(downloadResult.code).toBe(0);
      const downloadedBytes = fs.readFileSync(destPath, "utf8");
      expect(downloadedBytes).toBe(originalBytes);

      // C was never invited: cannot see the folder at all.
      const listC = await cliJson(["folder", "list"], envC);
      expect(listC.code).toBe(0);
      const folders = listC.json.folders as { id: string }[];
      expect(folders.some((f) => f.id === folderId)).toBe(false);
    },
    90000,
  );

  it(
    "CLI.3 folder members reports the right participants and roles",
    async () => {
      const dirA = freshProfileDir("membersA");
      const dirB = freshProfileDir("membersB");
      const envA = { SECURE_STORAGE_HOME: dirA };
      const envB = { SECURE_STORAGE_HOME: dirB };

      const userA = await registerProfile(dirA, "membersA");
      const userB = await registerProfile(dirB, "membersB");

      const folderRes = await cliJson(["folder", "create", "Roles"], envA);
      const folderId = folderRes.json.folderId as string;

      await cliJson(["folder", "share", folderId, userB.userId, "--role", "viewer"], envA);
      await cliJson(["folder", "join", folderId], envB);

      const membersRes = await waitFor(
        async () => {
          const res = await cliJson(["folder", "members", folderId], envA);
          const members = (res.json.members as { userId: string; role: string }[]) ?? [];
          return members.length >= 2 ? res : null;
        },
        { label: "both members visible", timeoutMs: 20000 },
      );
      expect(membersRes.code).toBe(0);
      const members = membersRes.json.members as { userId: string; role: string; membership: string }[];

      const owner = members.find((m) => m.userId === userA.userId);
      expect(owner?.role).toBe("owner");
      const viewer = members.find((m) => m.userId === userB.userId);
      expect(viewer?.role).toBe("viewer");
      expect(viewer?.membership).toBe("join");

      // Promote to editor and confirm `folder members` reflects it.
      await cliJson(["folder", "share", folderId, userB.userId, "--role", "editor"], envA);
      const updated = await waitFor(
        async () => {
          const res = await cliJson(["folder", "members", folderId], envA);
          const m = (res.json.members as { userId: string; role: string }[]).find(
            (x) => x.userId === userB.userId,
          );
          return m?.role === "editor" ? res : null;
        },
        { label: "role updated to editor", timeoutMs: 15000 },
      );
      const editor = (updated.json.members as { userId: string; role: string }[]).find(
        (m) => m.userId === userB.userId,
      );
      expect(editor?.role).toBe("editor");
    },
    60000,
  );

  it(
    "CLI.4 recovery restore on a fresh profile (new device) recovers a file via the CLI",
    async () => {
      const dir1 = freshProfileDir("recoverDev1");
      const env1 = { SECURE_STORAGE_HOME: dir1 };

      const user = await registerProfile(dir1, "recover");

      const folderRes = await cliJson(["folder", "create", "RecoverMe"], env1);
      const folderId = folderRes.json.folderId as string;

      const srcPath = path.join(dir1, "important.txt");
      const originalBytes = `recoverable content ${Math.random()}`;
      fs.writeFileSync(srcPath, originalBytes);
      const uploadRes = await cliJson(["file", "upload", folderId, srcPath], env1);
      const fileId = uploadRes.json.fileId as string;

      const setupRes = await cliJson(["recovery", "setup"], env1);
      expect(setupRes.code).toBe(0);
      const recoveryKey = setupRes.json.recoveryKey as string;
      expect(recoveryKey).toBeTruthy();

      // Give the key-backup upload a moment to actually land server-side —
      // poll the raw endpoint rather than assume, mirroring the library's
      // own 5.3 test (`isRecoverySetup` alone only proves the engine
      // believes it's active, not that this session's keys reached the
      // server yet).
      const accessTokenRes = JSON.parse(
        fs.readFileSync(path.join(dir1, "session.json"), "utf8"),
      ) as { accessToken: string };
      await waitFor(
        async () => {
          const res = await fetch(`${HOMESERVER}/_matrix/client/v3/room_keys/version`, {
            headers: { Authorization: `Bearer ${accessTokenRes.accessToken}` },
          });
          if (!res.ok) return null;
          const info = (await res.json()) as { count?: number };
          return (info.count ?? 0) >= 1 ? true : null;
        },
        { label: "server backup count >= 1", timeoutMs: 20000 },
      );

      // A genuinely new device for the SAME account: fresh profile dir (empty
      // crypto store) + `login` (mints a brand-new device_id/access_token).
      const dir2 = freshProfileDir("recoverDev2");
      const env2 = { SECURE_STORAGE_HOME: dir2 };
      const loginRes = await cliJson(
        [
          "login",
          "--homeserver",
          HOMESERVER,
          "--user",
          user.username,
          "--password",
          user.password,
        ],
        env2,
      );
      expect(loginRes.code).toBe(0);
      expect(loginRes.json.deviceId).not.toBe(undefined);

      // Negative control: before restoring, device 2 must NOT be able to
      // decrypt the file — proves the new device really does start empty.
      const destPath = path.join(dir2, "recovered.txt");
      const beforeRestore = await waitFor(
        async () => {
          // Poll until the folder/file are at least *visible* to device 2
          // (independent of decryption), so the eventual failure below is a
          // genuine decryption failure, not "folder not found yet".
          const listing = await cliJson(["file", "list", folderId], env2);
          const files = (listing.json.files as { id: string }[] | undefined) ?? [];
          return files.some((f) => f.id === fileId) ? listing : null;
        },
        { label: "device 2 sees the file", timeoutMs: 20000 },
      );
      expect(beforeRestore.code).toBe(0);
      const failedDownload = await cliJson(
        ["file", "download", folderId, fileId, destPath],
        env2,
      );
      expect(failedDownload.code).not.toBe(0);

      // Now restore from the Recovery Key and confirm the file recovers,
      // byte-identical to what device 1 originally uploaded.
      const restoreRes = await cliJson(["recovery", "restore", recoveryKey], env2);
      expect(restoreRes.code).toBe(0);
      expect(restoreRes.json.imported as number).toBeGreaterThan(0);

      const recovered = await waitFor(
        async () => {
          const res = await cliJson(["file", "download", folderId, fileId, destPath], env2);
          return res.code === 0 ? res : null;
        },
        { label: "device 2 decrypts after restore", timeoutMs: 20000 },
      );
      expect(recovered.code).toBe(0);
      expect(fs.readFileSync(destPath, "utf8")).toBe(originalBytes);
    },
    90000,
  );

  describe("CLI.5 error paths: clean non-zero exit + JSON error, no stack traces", () => {
    it("bad login credentials", async () => {
      const dir = freshProfileDir("badlogin");
      const res = await cliJson(
        [
          "login",
          "--homeserver",
          HOMESERVER,
          "--user",
          randomUser("nouser"),
          "--password",
          "wrong-password",
        ],
        { SECURE_STORAGE_HOME: dir },
      );
      expect(res.code).not.toBe(0);
      expect(typeof res.json.error).toBe("string");
      // stdout must be empty/unused on failure — the error goes to stderr,
      // and stderr itself must be exactly the one clean JSON line (parsing
      // it directly is the strongest proof there's no stack-trace dump).
      expect(res.stdout.trim()).toBe("");
      expect(() => JSON.parse(res.stderr.trim())).not.toThrow();
    });

    it("garbage recovery key", async () => {
      const dir = freshProfileDir("badrecovery");
      await registerProfile(dir, "badrecovery");
      const env = { SECURE_STORAGE_HOME: dir };

      const res = await cliJson(["recovery", "restore", "not a real recovery key"], env);
      expect(res.code).not.toBe(0);
      expect(typeof res.json.error).toBe("string");
      expect(() => JSON.parse(res.stderr.trim())).not.toThrow();
    });

    it(
      "download of a nonexistent file",
      async () => {
        const dir = freshProfileDir("missingfile");
        await registerProfile(dir, "missingfile");
        const env = { SECURE_STORAGE_HOME: dir };

        const folderRes = await cliJson(["folder", "create", "Empty"], env);
        const folderId = folderRes.json.folderId as string;

        const res = await cliJson(
          ["file", "download", folderId, "$doesnotexist12345", path.join(dir, "out.txt")],
          env,
        );
        expect(res.code).not.toBe(0);
        expect(typeof res.json.error).toBe("string");
        expect(() => JSON.parse(res.stderr.trim())).not.toThrow();
      },
      30000,
    );

    it("whoami with no session", async () => {
      const dir = freshProfileDir("nosession");
      const res = await cliJson(["whoami"], { SECURE_STORAGE_HOME: dir });
      expect(res.code).not.toBe(0);
      expect(res.json.error).toBe("not logged in");
    });

    it("non-json mode also exits non-zero with a clean single-line error, no stack trace", async () => {
      const dir = freshProfileDir("textmode");
      const result = await runCli(["whoami"], { SECURE_STORAGE_HOME: dir });
      expect(result.code).not.toBe(0);
      expect(result.stderr.trim()).toBe("Error: not logged in");
    });
  });
});
