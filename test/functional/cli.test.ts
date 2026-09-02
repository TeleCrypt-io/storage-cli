import { afterAll, describe, it, expect } from "vitest";
import { createServer } from "node:http";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { cleanupFreshProfiles, cliJson, freshProfileDir, markProfileForRemoteCleanup, runCli } from "../harness/cli";
import { approveDeviceCodeViaHttp } from "../harness/oidcApproval";
import { registerUserInMas } from "../harness/users";
import { waitFor } from "../harness/waitFor";
import type { Session } from "../../src/profile.js";
import { acquireProfileLock, sessionPath, writeSession } from "../../src/profile.js";

const HOMESERVER = "http://localhost:8008";
const testArtifactDirs = new Set<string>();

function artifactPath(name: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-cli-artifact-"));
  fs.chmodSync(dir, 0o700);
  testArtifactDirs.add(dir);
  return path.join(dir, name);
}

afterAll(async () => {
  try {
    await cleanupFreshProfiles();
  } finally {
    for (const dir of testArtifactDirs) fs.rmSync(dir, { recursive: true, force: true });
  }
});

function randomUser(prefix: string): string {
  // MAS enforces lowercase Matrix localparts.
  return `${prefix}_${Math.random().toString(36).slice(2, 8)}`.toLowerCase();
}

interface LocalMasUser {
  username: string;
  password: string;
}

/** Drives the product CLI's actual device-code flow. The test password is
 * used only by the local MAS browser-form approval helper. */
async function loginProfileOnce(
  dir: string,
  user: LocalMasUser,
): Promise<{ userId: string; username: string; password: string }> {
  let approval: Promise<void> | undefined;
  let approvalFailure: Error | undefined;
  const approvalAbort = new AbortController();
  const approvalDeadline = setTimeout(
    () => approvalAbort.abort(new Error("local MAS device approval timed out after 30s")),
    30_000,
  );
  let result;
  try {
    result = await runCli(
      ["storage", "login", "--homeserver", HOMESERVER, "--no-browser", "--json"],
      {
        TELECRYPT_IO_STORAGE_HOME: dir,
      },
      {
        abortSignal: approvalAbort.signal,
        onStderr(stderr) {
          const match = stderr.match(/and enter code: ([^\s]+)/);
          if (!match || approval) return;
          approval = approveDeviceCodeViaHttp(user.username, user.password, match[1], approvalAbort.signal).catch((err) => {
            approvalFailure = new Error(`local MAS device approval failed: ${(err as Error).message}`);
            approvalAbort.abort(approvalFailure);
          });
        },
      },
    );
  } finally {
    clearTimeout(approvalDeadline);
  }
  if (!approval) throw new Error(`CLI did not print an OIDC device code: ${result.stderr}`);
  await approval;
  if (approvalFailure) throw approvalFailure;
  expect(result.code).toBe(0);
  const json = JSON.parse(result.stdout) as { userId: string };
  return { userId: json.userId, ...user };
}

/** `mas-cli manage register-user` returns before its asynchronous Matrix
 * provisioning job always settles. Retrying the full OIDC flow observes that
 * real boundary without bypassing the OIDC flow through a direct password API. */
async function loginProfile(
  dir: string,
  user: LocalMasUser,
): Promise<{ userId: string; username: string; password: string }> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      return await loginProfileOnce(dir, user);
    } catch (err) {
      lastError = err;
      if (attempt < 3) {
        // A device grant can leave login-pending.json when initialization
        // fails after remote authorization. Revoke and clear that exact
        // profile before retrying; otherwise the CLI's fresh-profile fence
        // correctly refuses every subsequent attempt.
        const cleanup = await runCli(
          ["storage", "logout", "--json"],
          { TELECRYPT_IO_STORAGE_HOME: dir },
          { timeoutMs: 20_000 },
        );
        if (cleanup.code !== 0) throw lastError;
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }
  }
  throw lastError;
}

async function registerProfile(
  dir: string,
  prefix: string,
): Promise<{ userId: string; username: string; password: string }> {
  const username = randomUser(prefix);
  const password = "pw_" + Math.random().toString(36).slice(2, 10);
  await registerUserInMas(username, password);
  // Mark the profile before authorization begins: a device grant can issue a
  // bearer session before local persistence completes, leaving only the
  // retryable pending file for teardown to revoke.
  markProfileForRemoteCleanup(dir);
  const profile = await loginProfile(dir, { username, password });
  return profile;
}

describe("CLI", () => {
  it("fences a concurrent read command while a profile transaction owns the lock", async () => {
    const dir = freshProfileDir("concurrent-profile");
    const session: Session = {
      homeserver: HOMESERVER,
      userId: "@concurrent:example.test",
      matrixServerName: "example.test",
      deviceId: "CONCURRENTDEVICE",
      accessToken: "concurrent-access-token",
      oidcIssuer: `${HOMESERVER}/auth/`,
      refreshToken: "concurrent-refresh-token",
      oidcClientId: "concurrent-client",
      oidcTokenEndpoint: `${HOMESERVER}/auth/token`,
      oidcRevocationEndpoint: `${HOMESERVER}/auth/revoke`,
    };
    writeSession(session, dir);
    const lock = acquireProfileLock(dir);
    try {
      const blocked = await runCli(["storage", "whoami", "--json"], {
        TELECRYPT_IO_STORAGE_HOME: dir,
      });
      expect(blocked.code).not.toBe(0);
      expect(JSON.parse(blocked.stderr)).toEqual({
        error: "profile is busy; retry after the other storage command exits",
      });
      expect(blocked.stderr).not.toContain(session.accessToken);
    } finally {
      lock.release();
    }
    const after = await runCli(["storage", "whoami", "--json"], {
      TELECRYPT_IO_STORAGE_HOME: dir,
    });
    expect(after.code).toBe(0);
    expect(JSON.parse(after.stdout)).toMatchObject({ userId: session.userId, deviceId: session.deviceId });
  });

  it("logout exits nonzero and retains the profile when server revocation fails", async () => {
    const dir = freshProfileDir("logout-failure");
    const server = createServer((_request, response) => {
      response.writeHead(503);
      response.end();
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    try {
      const address = server.address();
      if (!address || typeof address === "string") throw new Error("test server did not expose a port");
      const session: Session = {
        homeserver: `http://127.0.0.1:${address.port}`,
        userId: "@logout:example.test",
        matrixServerName: "example.test",
        deviceId: "LOGOUTDEVICE",
        accessToken: "logout-access-token",
        oidcIssuer: `http://127.0.0.1:${address.port}/auth/`,
        refreshToken: "logout-refresh-token",
        oidcClientId: "logout-client",
        oidcTokenEndpoint: `http://127.0.0.1:${address.port}/auth/token`,
        oidcRevocationEndpoint: `http://127.0.0.1:${address.port}/auth/revoke`,
      };
    writeSession(session, dir);

      const result = await runCli(["storage", "logout", "--json"], {
        TELECRYPT_IO_STORAGE_HOME: dir,
      });

      expect(result.code).not.toBe(0);
      expect(JSON.parse(result.stderr)).toEqual({ error: "server logout failed (HTTP 503)" });
      expect(result.stderr).not.toContain(session.accessToken);
      expect(fs.existsSync(sessionPath(dir))).toBe(true);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
    }
  });

  it(
    "CLI.1 cross-process persistence: upload in one process, download in a separate one, byte-identical",
    async () => {
      const dir = freshProfileDir("persist");
      const env = { TELECRYPT_IO_STORAGE_HOME: dir };

      // Every step below is its OWN subprocess — this is the mandatory proof
      // that the Matrix session + megolm keys survive across process exits.
      await registerProfile(dir, "persist");

      const recoverySetup = await cliJson(["storage", "recovery", "setup"], env);
      expect(recoverySetup.code).toBe(0);
      expect(typeof recoverySetup.json.recoveryKey).toBe("string");

      const vaultRes = await cliJson(["storage", "vault", "create", "PersistVault"], env);
      expect(vaultRes.code).toBe(0);
      const vaultId = vaultRes.json.id as string;
      expect(vaultId).toBeTruthy();

      const srcPath = artifactPath("source.txt");
      const originalBytes = `cross-process proof ${Math.random()}`;
      fs.writeFileSync(srcPath, originalBytes);

      const uploadRes = await cliJson(["storage", "file", "upload", vaultId, srcPath], env);
      expect(uploadRes.code).toBe(0);
      const fileId = uploadRes.json.id as string;
      expect(fileId).toBeTruthy();

      // A completely fresh process, no state shared except the profile dir on
      // disk: this is the actual proof. If crypto persistence failed, this
      // would throw a decryption error (empty megolm store).
      const destPath = artifactPath("downloaded.txt");
      const downloadRes = await cliJson(
        ["storage", "file", "download", vaultId, fileId, destPath],
        env,
      );
      expect(downloadRes.code).toBe(0);

      const downloadedBytes = fs.readFileSync(destPath, "utf8");
      expect(downloadedBytes).toBe(originalBytes);
    },
    60000,
  );

  it(
    "CLI.2 multi-participant shared vault: B uploads, A downloads B's file byte-identical; uninvited C cannot list it",
    async () => {
      const dirA = freshProfileDir("multiA");
      const dirB = freshProfileDir("multiB");
      const dirC = freshProfileDir("multiC");
      const envA = { TELECRYPT_IO_STORAGE_HOME: dirA };
      const envB = { TELECRYPT_IO_STORAGE_HOME: dirB };
      const envC = { TELECRYPT_IO_STORAGE_HOME: dirC };

      await registerProfile(dirA, "multiA");
      const userB = await registerProfile(dirB, "multiB");
      await registerProfile(dirC, "multiC");

      const vaultRes = await cliJson(["storage", "vault", "create", "Shared"], envA);
      expect(vaultRes.code).toBe(0);
      const vaultId = vaultRes.json.id as string;

      const shareRes = await cliJson(
        ["storage", "vault", "share", vaultId, userB.userId, "--role", "editor"],
        envA,
      );
      expect(shareRes.code).toBe(0);
      expect(shareRes.json).toMatchObject({ vaultId, userId: userB.userId, role: "editor" });

      const joinRes = await cliJson(["storage", "vault", "join", vaultId], envB);
      expect(joinRes.code).toBe(0);

      const srcPath = artifactPath("from-b.txt");
      const originalBytes = `B's file ${Math.random()}`;
      fs.writeFileSync(srcPath, originalBytes);

      const uploadRes = await cliJson(["storage", "file", "upload", vaultId, srcPath], envB);
      expect(uploadRes.code).toBe(0);
      const fileId = uploadRes.json.id as string;

      // A downloads B's file. The megolm key-share to-device message is
      // awaited as part of B's upload resolving, so this should generally
      // succeed on the first try — but poll the real condition (repeated
      // fresh CLI invocations, each a genuine independent sync) rather than
      // assume, since key delivery is still asynchronous end-to-end.
      const destPath = artifactPath("from-b-downloaded.txt");
      const downloadResult = await waitFor(
        async (attemptSignal) => {
          const res = await cliJson(["storage", "file", "download", vaultId, fileId, destPath], envA, { abortSignal: attemptSignal });
          return res.code === 0 ? res : null;
        },
        { label: "A decrypts B's file", timeoutMs: 30000, intervalMs: 1500 },
      );
      expect(downloadResult.code).toBe(0);
      const downloadedBytes = fs.readFileSync(destPath, "utf8");
      expect(downloadedBytes).toBe(originalBytes);

      // C was never invited: cannot see the vault at all.
      const listC = await cliJson(["storage", "vault", "list"], envC);
      expect(listC.code).toBe(0);
      const vaults = listC.json.vaults as { id: string }[];
      expect(vaults.some((f) => f.id === vaultId)).toBe(false);
    },
    90000,
  );

  it(
    "CLI.3 vault members reports the right participants and roles",
    async () => {
      const dirA = freshProfileDir("membersA");
      const dirB = freshProfileDir("membersB");
      const envA = { TELECRYPT_IO_STORAGE_HOME: dirA };
      const envB = { TELECRYPT_IO_STORAGE_HOME: dirB };

      const userA = await registerProfile(dirA, "membersA");
      const userB = await registerProfile(dirB, "membersB");

      const vaultRes = await cliJson(["storage", "vault", "create", "Roles"], envA);
      const vaultId = vaultRes.json.id as string;

      await cliJson(["storage", "vault", "share", vaultId, userB.userId, "--role", "viewer"], envA);
      await cliJson(["storage", "vault", "join", vaultId], envB);

      const membersRes = await waitFor(
        async (attemptSignal) => {
          const res = await cliJson(["storage", "vault", "members", vaultId], envA, { abortSignal: attemptSignal });
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

      // Promote to editor and confirm `vault members` reflects it.
      await cliJson(["storage", "vault", "share", vaultId, userB.userId, "--role", "editor"], envA);
      const updated = await waitFor(
        async (attemptSignal) => {
          const res = await cliJson(["storage", "vault", "members", vaultId], envA, { abortSignal: attemptSignal });
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
      const env1 = { TELECRYPT_IO_STORAGE_HOME: dir1 };

      const user = await registerProfile(dir1, "recover");

      const vaultRes = await cliJson(["storage", "vault", "create", "RecoverMe"], env1);
      const vaultId = vaultRes.json.id as string;

      const srcPath = artifactPath("important.txt");
      const originalBytes = `recoverable content ${Math.random()}`;
      fs.writeFileSync(srcPath, originalBytes);
      const uploadRes = await cliJson(["storage", "file", "upload", vaultId, srcPath], env1);
      const fileId = uploadRes.json.id as string;

      const setupRes = await cliJson(["storage", "recovery", "setup"], env1);
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
        async (attemptSignal) => {
          const res = await fetch(`${HOMESERVER}/_matrix/client/v3/room_keys/version`, {
            headers: { Authorization: `Bearer ${accessTokenRes.accessToken}` },
            signal: attemptSignal,
          });
          if (!res.ok) return null;
          const info = (await res.json()) as { count?: number };
          return (info.count ?? 0) >= 1 ? true : null;
        },
        { label: "server backup count >= 1", timeoutMs: 20000 },
      );

      // A genuinely new device for the SAME account: fresh profile dir (empty
      // crypto store) + a second MAS OIDC device authorization.
      const dir2 = freshProfileDir("recoverDev2");
      const env2 = { TELECRYPT_IO_STORAGE_HOME: dir2 };
      markProfileForRemoteCleanup(dir2);
      const newDevice = await loginProfile(dir2, user);
      expect(newDevice.userId).toBe(user.userId);

      // Negative control: before restoring, device 2 must NOT be able to
      // decrypt the file — proves the new device really does start empty.
      const destPath = artifactPath("recovered.txt");
      const beforeRestore = await waitFor(
        async (attemptSignal) => {
          // Poll until the vault/file are at least *visible* to device 2
          // (independent of decryption), so the eventual failure below is a
          // genuine decryption failure, not "vault not found yet".
          const listing = await cliJson(["storage", "file", "list", vaultId], env2, { abortSignal: attemptSignal });
          const files = (listing.json.files as { id: string }[] | undefined) ?? [];
          return files.some((f) => f.id === fileId) ? listing : null;
        },
        { label: "device 2 sees the file", timeoutMs: 20000 },
      );
      expect(beforeRestore.code).toBe(0);
      const failedDownload = await cliJson(
        ["storage", "file", "download", vaultId, fileId, destPath],
        env2,
      );
      expect(failedDownload.code).not.toBe(0);

      // Now restore from the Recovery Key and confirm the file recovers,
      // byte-identical to what device 1 originally uploaded.
      const restoreRes = await cliJson(
        ["storage", "recovery", "restore", "--key-stdin"],
        env2,
        { stdin: recoveryKey },
      );
      expect(restoreRes.code).toBe(0);
      expect(restoreRes.json.imported as number).toBeGreaterThan(0);

      const recovered = await waitFor(
        async (attemptSignal) => {
          const res = await cliJson(["storage", "file", "download", vaultId, fileId, destPath], env2, { abortSignal: attemptSignal });
          return res.code === 0 ? res : null;
        },
        { label: "device 2 decrypts after restore", timeoutMs: 20000 },
      );
      expect(recovered.code).toBe(0);
      expect(fs.readFileSync(destPath, "utf8")).toBe(originalBytes);
    },
    90000,
  );

  it(
    "CLI.5 UI-equivalent tree operations: folders and files can be created, renamed, listed, and deleted",
    async () => {
      const dir = freshProfileDir("tree");
      const env = { TELECRYPT_IO_STORAGE_HOME: dir };
      await registerProfile(dir, "tree");

      const parent = await cliJson(["storage", "vault", "create", "Parent"], env);
      expect(parent.code).toBe(0);
      const parentId = parent.json.id as string;

      const child = await cliJson(
        ["storage", "vault", "subfolder", "create", parentId, "Child"],
        env,
      );
      expect(child.code).toBe(0);
      const childId = child.json.id as string;

      const initialFolders = await cliJson(
        ["storage", "vault", "subfolder", "list", parentId],
        env,
      );
      expect(initialFolders.code).toBe(0);
      expect(initialFolders.json.folders).toEqual(
        expect.arrayContaining([expect.objectContaining({ id: childId, name: "Child" })]),
      );

      const renameChild = await cliJson(
        ["storage", "vault", "subfolder", "rename", childId, "Child Renamed"],
        env,
      );
      expect(renameChild.code).toBe(0);
      expect(renameChild.json).toMatchObject({ id: childId, name: "Child Renamed" });

      const source = artifactPath("before-rename.txt");
      fs.writeFileSync(source, `tree operation proof ${Math.random()}`);
      const upload = await cliJson(["storage", "file", "upload", parentId, source], env);
      expect(upload.code).toBe(0);
      const fileId = upload.json.id as string;

      const renameFile = await cliJson(
        ["storage", "file", "rename", parentId, fileId, "after-rename.txt"],
        env,
      );
      expect(renameFile.code).toBe(0);
      expect(renameFile.json).toMatchObject({ id: fileId, name: "after-rename.txt" });

      const filesAfterRename = await cliJson(["storage", "file", "list", parentId], env);
      expect(filesAfterRename.code).toBe(0);
      expect(filesAfterRename.json.files).toEqual(
        expect.arrayContaining([expect.objectContaining({ id: fileId, name: "after-rename.txt" })]),
      );

      const deleteFile = await cliJson(["storage", "file", "delete", parentId, fileId], env);
      expect(deleteFile.code).toBe(0);
      expect(deleteFile.json).toMatchObject({ id: fileId, deleted: true });

      const filesAfterDelete = await cliJson(["storage", "file", "list", parentId], env);
      expect(filesAfterDelete.code).toBe(0);
      expect(filesAfterDelete.json.files).not.toEqual(
        expect.arrayContaining([expect.objectContaining({ id: fileId })]),
      );

      const deleteChild = await cliJson(["storage", "vault", "subfolder", "delete", childId], env);
      expect(deleteChild.code).toBe(0);
      expect(deleteChild.json).toMatchObject({ id: childId, deleted: true });

      const renameParent = await cliJson(
        ["storage", "vault", "rename", parentId, "Parent Renamed"],
        env,
      );
      expect(renameParent.code).toBe(0);
      expect(renameParent.json).toMatchObject({ id: parentId, name: "Parent Renamed" });

      const deleteParent = await cliJson(["storage", "vault", "delete", parentId], env);
      expect(deleteParent.code).toBe(0);
      expect(deleteParent.json).toMatchObject({ id: parentId, deleted: true });
    },
    60000,
  );

  describe("CLI.6 error paths: clean non-zero exit + JSON error, no stack traces", () => {
    it("renders commander parse errors as one JSON diagnostic", async () => {
      const dir = freshProfileDir("json-parse-error");
      const res = await cliJson(["storage", "command-that-does-not-exist"], {
        TELECRYPT_IO_STORAGE_HOME: dir,
      });
      expect(res.code).not.toBe(0);
      expect(res.stdout.trim()).toBe("");
      expect(typeof res.json.error).toBe("string");
      expect(res.stderr.trim().startsWith("{")).toBe(true);
    });

    it("login rejects a local endpoint without Matrix OIDC discovery", async () => {
      const dir = freshProfileDir("missing-oidc");
      const res = await cliJson(
        ["storage", "login", "--homeserver", `${HOMESERVER}/not-a-homeserver`, "--no-browser"],
        {
          TELECRYPT_IO_STORAGE_HOME: dir,
        },
      );
      expect(res.code).not.toBe(0);
      expect(typeof res.json.error).toBe("string");
      expect(res.stdout.trim()).toBe("");
      expect(() => JSON.parse(res.stderr.trim())).not.toThrow();
    });

    it("garbage recovery key", async () => {
      const dir = freshProfileDir("badrecovery");
      await registerProfile(dir, "badrecovery");
      const env = { TELECRYPT_IO_STORAGE_HOME: dir };

      const res = await cliJson(
        ["storage", "recovery", "restore", "--key-stdin"],
        env,
        { stdin: "not a real recovery key" },
      );
      expect(res.code).not.toBe(0);
      expect(typeof res.json.error).toBe("string");
      expect(() => JSON.parse(res.stderr.trim())).not.toThrow();
    });

    it(
      "download of a nonexistent file",
      async () => {
        const dir = freshProfileDir("missingfile");
        await registerProfile(dir, "missingfile");
        const env = { TELECRYPT_IO_STORAGE_HOME: dir };

        const vaultRes = await cliJson(["storage", "vault", "create", "Empty"], env);
        const vaultId = vaultRes.json.id as string;

        const res = await cliJson(
          ["storage", "file", "download", vaultId, "$doesnotexist12345", artifactPath("out.txt")],
          env,
        );
        expect(res.code).not.toBe(0);
        expect(typeof res.json.error).toBe("string");
        expect(() => JSON.parse(res.stderr.trim())).not.toThrow();
      },
      // A fresh CLI process must initialize crypto and sync with the
      // disposable test server. That server may be slow; revisit this 60s
      // budget if it becomes consistently faster.
      60000,
    );

    it("whoami with no session", async () => {
      const dir = freshProfileDir("nosession");
      const res = await cliJson(["storage", "whoami"], { TELECRYPT_IO_STORAGE_HOME: dir });
      expect(res.code).not.toBe(0);
      expect(res.json.error).toBe("not logged in");
    });

    it("non-json mode also exits non-zero with a clean single-line error, no stack trace", async () => {
      const dir = freshProfileDir("textmode");
      const result = await runCli(["storage", "whoami"], { TELECRYPT_IO_STORAGE_HOME: dir });
      expect(result.code).not.toBe(0);
      expect(result.stderr.trim()).toBe("Error: not logged in");
    });
  });
});
