import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { once } from "node:events";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import {
  assertSecureProfileDir,
  assertFreshProfileUnlocked,
  acquireProfileLock,
  cryptoSnapshotPath,
  expectedMatrixServerName,
  isCanonicalMatrixUserId,
  MAX_SESSION_BYTES,
  pendingSessionPath,
  profileDir as configuredProfileDir,
  readPrivateFile,
  readSession,
  sessionPath,
  writePrivateFile,
  writePendingSessionUnlocked,
  writeSession,
  writeSessionUnlocked,
} from "../src/profile.js";
import { loadSnapshotFromDisk, saveSnapshotToDisk } from "../src/cryptoSnapshot.js";

const dirs: string[] = [];
const originalConfiguredHome = process.env.TELECRYPT_IO_STORAGE_HOME;

function profileDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-profile-test-"));
  fs.chmodSync(dir, 0o700);
  dirs.push(dir);
  return dir;
}

function session() {
  return {
    homeserver: "https://backend.telecrypt.io",
    userId: "@alice:telecrypt.io",
    matrixServerName: "telecrypt.io",
    deviceId: "DEVICE",
    accessToken: "access-token",
    oidcIssuer: "https://backend.telecrypt.io/",
    refreshToken: "refresh-token",
    oidcClientId: "client",
    oidcTokenEndpoint: "https://backend.telecrypt.io/token",
    oidcRevocationEndpoint: "https://backend.telecrypt.io/revoke",
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  if (originalConfiguredHome === undefined) delete process.env.TELECRYPT_IO_STORAGE_HOME;
  else process.env.TELECRYPT_IO_STORAGE_HOME = originalConfiguredHome;
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("secret-bearing CLI profile state", () => {
  it("requires an explicitly configured profile home to be canonical absolute", () => {
    for (const value of ["relative/profile", "", "/tmp/profile/", "/"]) {
      process.env.TELECRYPT_IO_STORAGE_HOME = value;
      expect(() => configuredProfileDir()).toThrow(/canonical absolute/u);
    }
    const dir = profileDir();
    process.env.TELECRYPT_IO_STORAGE_HOME = dir;
    expect(configuredProfileDir()).toBe(dir);
  });

  it("binds only exact canonical MXIDs to the independently trusted TeleCrypt topology", () => {
    expect(expectedMatrixServerName("https://backend.telecrypt.io")).toBe("telecrypt.io");
    expect(expectedMatrixServerName("https://backend.stage.telecrypt.io")).toBe("stage.telecrypt.io");
    expect(expectedMatrixServerName("https://backend-stage.telecrypt.io")).toBeNull();
    expect(expectedMatrixServerName("https://backend.telecrypt.io:443")).toBeNull();
    expect(expectedMatrixServerName("https://backend.telecrypt.io/path")).toBeNull();
    expect(expectedMatrixServerName("http://localhost:8008")).toBe("example.test");
    expect(expectedMatrixServerName("http://localhost:8008/"))
      .toBe("example.test");
    expect(isCanonicalMatrixUserId("@alice:telecrypt.io")).toBe(true);
    expect(isCanonicalMatrixUserId("@Alice:telecrypt.io")).toBe(false);
    expect(isCanonicalMatrixUserId("@alice:telecrypt.io:0443")).toBe(false);
    expect(isCanonicalMatrixUserId("@alice:telecrypt.io:443")).toBe(true);
  });

  it("writes session and crypto state as private regular files", () => {
    const dir = profileDir();
    writeSession(session(), dir);
    saveSnapshotToDisk(cryptoSnapshotPath(dir), { dbs: [] });

    expect(fs.lstatSync(sessionPath(dir)).isFile()).toBe(true);
    expect(fs.lstatSync(sessionPath(dir)).mode & 0o077).toBe(0);
    expect(fs.lstatSync(cryptoSnapshotPath(dir)).mode & 0o077).toBe(0);
    expect(readSession(dir)).toEqual(session());
    expect(loadSnapshotFromDisk(cryptoSnapshotPath(dir))).toEqual({ dbs: [] });
  });

  it("rejects an incomplete OIDC session", () => {
    const dir = profileDir();
    fs.writeFileSync(sessionPath(dir), JSON.stringify({ ...session(), refreshToken: "" }), { mode: 0o600 });
    expect(() => readSession(dir)).toThrow(/not a valid OIDC\/MAS session/);
  });

  it("rejects a pre-issuer session instead of attempting refresh with ambiguous metadata", () => {
    const dir = profileDir();
    const persisted = { ...session() } as Record<string, unknown>;
    delete persisted.oidcIssuer;
    fs.writeFileSync(sessionPath(dir), JSON.stringify(persisted), { mode: 0o600 });
    expect(() => readSession(dir)).toThrow(/not a valid OIDC\/MAS session/);
  });

  it("rejects an unsafe persisted OIDC revocation endpoint", () => {
    const dir = profileDir();
    fs.writeFileSync(
      sessionPath(dir),
      JSON.stringify({ ...session(), oidcRevocationEndpoint: "https://evil.example/revoke" }),
      { mode: 0o600 },
    );
    expect(() => readSession(dir)).toThrow(/not a valid OIDC\/MAS session/);
  });

  it("rejects a persisted session without a device identity before storage can open", () => {
    const dir = profileDir();
    const persisted = { ...session() } as Record<string, unknown>;
    delete persisted.deviceId;
    fs.writeFileSync(sessionPath(dir), JSON.stringify(persisted), { mode: 0o600 });
    expect(() => readSession(dir)).toThrow(/not a valid OIDC\/MAS session/);
  });

  it("rejects a session whose Matrix server binding does not match the MXID", () => {
    const dir = profileDir();
    fs.writeFileSync(
      sessionPath(dir),
      JSON.stringify({ ...session(), matrixServerName: "other.telecrypt.io" }),
      { mode: 0o600 },
    );
    expect(() => readSession(dir)).toThrow(/not a valid OIDC\/MAS session/);
  });

  it("accepts canonical plus localparts and rejects unsafe server names", () => {
    const dir = profileDir();
    writeSession({ ...session(), userId: "@alice+tag:telecrypt.io", matrixServerName: "telecrypt.io" }, dir);
    expect(readSession(dir)?.userId).toBe("@alice+tag:telecrypt.io");
    fs.writeFileSync(
      sessionPath(dir),
      JSON.stringify({ ...session(), userId: "@alice:telecrypt.io/path", matrixServerName: "telecrypt.io/path" }),
      { mode: 0o600 },
    );
    expect(() => readSession(dir)).toThrow(/not a valid OIDC\/MAS session/);
  });

  it.each(["session", "crypto snapshot", "logout marker"])("refuses login over existing %s state", (state) => {
    const dir = profileDir();
    if (state === "session") writeSession(session(), dir);
    if (state === "crypto snapshot") saveSnapshotToDisk(cryptoSnapshotPath(dir), { dbs: [] });
    if (state === "logout marker") fs.writeFileSync(path.join(dir, "logout-complete"), "server-revoked\n", { mode: 0o600 });
    expect(() => assertFreshProfileUnlocked(dir)).toThrow(/profile is not empty/);
  });

  it("bounds session reads and serializes concurrent profile writers", () => {
    const dir = profileDir();
    fs.writeFileSync(sessionPath(dir), "x".repeat(MAX_SESSION_BYTES + 1), { mode: 0o600 });
    expect(() => readSession(dir)).toThrow(/maximum size/);

    fs.rmSync(sessionPath(dir));
    const first = acquireProfileLock(dir);
    expect(() => acquireProfileLock(dir)).toThrow(/profile is busy/);
    first.release();
    const second = acquireProfileLock(dir);
    second.release();
  });

  it("rejects an aggregate session larger than the bounded read size before writing", () => {
    const dir = profileDir();
    const oversized = session();
    oversized.accessToken = "a".repeat(6_000);
    oversized.refreshToken = "b".repeat(6_000);
    oversized.oidcClientId = "c".repeat(6_000);

    expect(() => writeSession(oversized, dir)).toThrow(
      `profile session exceeds maximum size of ${MAX_SESSION_BYTES} bytes`,
    );
    expect(fs.existsSync(sessionPath(dir))).toBe(false);
  });

  it("rejects an aggregate pending login state larger than the bounded read size before writing", () => {
    const dir = profileDir();
    const oversized = {
      homeserver: "https://backend.telecrypt.io",
      deviceId: "DEVICE",
      accessToken: "a".repeat(6_000),
      oidcIssuer: "https://backend.telecrypt.io/",
      refreshToken: "b".repeat(6_000),
      oidcClientId: "c".repeat(6_000),
      oidcTokenEndpoint: "https://backend.telecrypt.io/token",
      oidcRevocationEndpoint: "https://backend.telecrypt.io/revoke",
      matrixServerName: "telecrypt.io",
    };

    expect(() => writePendingSessionUnlocked(oversized, dir)).toThrow(
      `pending login state exceeds maximum size of ${MAX_SESSION_BYTES} bytes`,
    );
    expect(fs.existsSync(pendingSessionPath(dir))).toBe(false);
  });

  it("recovers a stale PID lock but fences a live process", async () => {
    const dir = profileDir();
    let stalePid = 2 ** 30;
    while (true) {
      try {
        process.kill(stalePid, 0);
        stalePid += 1;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ESRCH") break;
        throw error;
      }
    }
    const lockPath = path.join(dir, ".profile.lock");
    fs.writeFileSync(lockPath, JSON.stringify({ pid: stalePid, token: "stale" }), { mode: 0o600 });
    const recovered = acquireProfileLock(dir);
    recovered.release();

    const moduleUrl = pathToFileURL(path.resolve("src/profile.ts")).href;
    const child = spawn(
      process.execPath,
      ["--experimental-strip-types", "--input-type=module", "-e", `import { acquireProfileLock } from ${JSON.stringify(moduleUrl)}; const lock = acquireProfileLock(${JSON.stringify(dir)}); process.stdout.write("locked\\n"); setTimeout(() => {}, 5000);`],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
    try {
      await new Promise<void>((resolve, reject) => {
        const startupTimeout = setTimeout(() => {
          cleanup();
          reject(new Error("profile lock child did not become ready"));
        }, 2_000);
        const onData = (): void => {
          cleanup();
          resolve();
        };
        const onError = (error: Error): void => {
          cleanup();
          reject(error);
        };
        const onExit = (code: number | null, signal: NodeJS.Signals | null): void => {
          cleanup();
          reject(new Error(`profile lock child exited before becoming ready (${code ?? signal ?? "unknown"})`));
        };
        const cleanup = (): void => {
          clearTimeout(startupTimeout);
          child.stdout?.off("data", onData);
          child.off("error", onError);
          child.off("exit", onExit);
        };
        child.stdout?.once("data", onData);
        child.once("error", onError);
        child.once("exit", onExit);
      });
      expect(() => acquireProfileLock(dir)).toThrow(/profile is busy/);
      child.kill("SIGTERM");
      if (child.exitCode === null && child.signalCode === null) await once(child, "exit");
      const afterExit = acquireProfileLock(dir);
      afterExit.release();
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill("SIGTERM");
        await once(child, "exit").catch(() => undefined);
      }
    }
  });

  it("does not unlink a replacement lock during stale recovery interleaving", () => {
    const dir = profileDir();
    let stalePid = 2 ** 30;
    while (true) {
      try {
        process.kill(stalePid, 0);
        stalePid += 1;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ESRCH") break;
        throw error;
      }
    }
    const lockPath = path.join(dir, ".profile.lock");
    const stale = JSON.stringify({ pid: stalePid, token: "stale" });
    const replacement = JSON.stringify({ pid: process.pid, token: "replacement" });
    fs.writeFileSync(lockPath, stale, { mode: 0o600 });
    const originalRename = fs.renameSync;
    let interleaved = false;
    const rename = vi.spyOn(fs, "renameSync").mockImplementation(((from, to) => {
      if (!interleaved && String(from).endsWith("/.profile.lock") && String(to).endsWith(".stale")) {
        interleaved = true;
        fs.writeFileSync(lockPath, replacement, { mode: 0o600 });
      }
      return originalRename(from, to);
    }) as typeof fs.renameSync);
    try {
      expect(() => acquireProfileLock(dir)).toThrow(/profile is busy/);
      expect(fs.readFileSync(lockPath, "utf8")).toBe(replacement);
    } finally {
      rename.mockRestore();
      fs.rmSync(lockPath, { force: true });
    }
  });

  it("does not overwrite a lock acquired after stale quarantine", () => {
    const dir = profileDir();
    let stalePid = 2 ** 30;
    while (true) {
      try {
        process.kill(stalePid, 0);
        stalePid += 1;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ESRCH") break;
        throw error;
      }
    }
    const lockPath = path.join(dir, ".profile.lock");
    const stale = JSON.stringify({ pid: stalePid, token: "stale" });
    const replacement = JSON.stringify({ pid: process.pid, token: "replacement" });
    fs.writeFileSync(lockPath, stale, { mode: 0o600 });
    const originalRename = fs.renameSync;
    const rename = vi.spyOn(fs, "renameSync").mockImplementation(((from, to) => {
      const result = originalRename(from, to);
      if (String(to).endsWith(".stale")) fs.writeFileSync(to, replacement, { mode: 0o600 });
      return result;
    }) as typeof fs.renameSync);
    const originalLink = fs.linkSync;
    const link = vi.spyOn(fs, "linkSync").mockImplementation(((from, to) => {
      if (String(to).endsWith("/.profile.lock")) fs.writeFileSync(lockPath, replacement, { mode: 0o600 });
      return originalLink(from, to);
    }) as typeof fs.linkSync);
    try {
      expect(() => acquireProfileLock(dir)).toThrow(/profile is busy/);
      expect(fs.readFileSync(lockPath, "utf8")).toBe(replacement);
    } finally {
      rename.mockRestore();
      link.mockRestore();
      fs.rmSync(lockPath, { force: true });
    }
  });

  it("keeps the previous private file when atomic replacement fails", () => {
    const dir = profileDir();
    const destination = sessionPath(dir);
    fs.writeFileSync(destination, "old", { mode: 0o600 });
    const originalRename = fs.renameSync;
    const rename = vi.spyOn(fs, "renameSync").mockImplementation(((from, to) => {
      if (String(to) === destination || String(to).endsWith("/session.json")) throw new Error("simulated atomic rename failure");
      return originalRename(from, to);
    }) as typeof fs.renameSync);
    try {
      expect(() => writePrivateFile(destination, "new")).toThrow("simulated atomic rename failure");
      expect(fs.readFileSync(destination, "utf8")).toBe("old");
      expect(fs.readdirSync(dir).filter((entry) => entry.includes(".session.json-")).length).toBe(0);
    } finally {
      rename.mockRestore();
    }
  });

  it("uses the retained directory handle when the profile pathname is replaced", () => {
    const dir = profileDir();
    const originalDirectory = `${dir}-original`;
    dirs.push(originalDirectory);
    const lock = acquireProfileLock(dir);
    try {
      fs.renameSync(dir, originalDirectory);
      fs.mkdirSync(dir, { mode: 0o700 });
      writeSessionUnlocked(session(), dir, lock);
      expect(fs.existsSync(path.join(originalDirectory, "session.json"))).toBe(true);
      expect(fs.existsSync(path.join(dir, "session.json"))).toBe(false);
    } finally {
      lock.release();
    }
  });

  it("does not corrupt the returned buffer when verification reads are short", () => {
    const dir = profileDir();
    const target = path.join(dir, "large-private-state");
    const expected = Buffer.alloc(128 * 1024, 0).map((_value, index) => index % 251);
    writePrivateFile(target, expected);
    const originalRead = fs.readSync;
    vi.spyOn(fs, "readSync").mockImplementation(((fd, buffer, offset, length, position) =>
      originalRead(fd, buffer, offset, position === null ? length : Math.min(length, 7), position)
    ) as typeof fs.readSync);

    expect(readPrivateFile(target, expected.length)).toEqual(expected);
  });

  it("rejects an owner-writable shared ancestor without the root sticky-directory contract", () => {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-untrusted-ancestor-"));
    dirs.push(parent);
    fs.chmodSync(parent, 0o777);
    const child = path.join(parent, "profile");
    fs.mkdirSync(child, { mode: 0o700 });
    expect(() => acquireProfileLock(child)).toThrow(/untrusted writable ancestor/);
  });

  it("surfaces and retries a lock release failure after quarantine", () => {
    const dir = profileDir();
    const lock = acquireProfileLock(dir);
    const originalRemove = fs.rmSync;
    let failOnce = true;
    const remove = vi.spyOn(fs, "rmSync").mockImplementation(((target, options) => {
      if (failOnce && String(target).endsWith(".release")) {
        failOnce = false;
        throw new Error("simulated release failure");
      }
      return originalRemove(target, options);
    }) as typeof fs.rmSync);
    try {
      expect(() => lock.release()).toThrow("profile lock cleanup failed");
      expect(fs.readdirSync(dir).some((entry) => entry.endsWith(".release"))).toBe(true);
      lock.release();
      expect(fs.readdirSync(dir).some((entry) => entry.endsWith(".release"))).toBe(false);
    } finally {
      remove.mockRestore();
    }
  });

  it("rejects a group-readable profile directory before loading state", () => {
    const dir = profileDir();
    fs.chmodSync(dir, 0o750);
    expect(() => readSession(dir)).toThrow(/accessible by group or other users/);
  });

  it("rejects a symlinked profile directory before loading state", () => {
    const target = profileDir();
    const link = `${target}-link`;
    fs.symlinkSync(target, link);
    dirs.push(link);
    expect(() => readSession(link)).toThrow(/profile directory must not be a symlink/);
  });

  it("rejects symlinked, non-regular, and group-readable secret files", () => {
    const dir = profileDir();
    const target = path.join(dir, "target");
    fs.writeFileSync(target, "{}", { mode: 0o600 });
    fs.symlinkSync(target, sessionPath(dir));
    expect(() => readSession(dir)).toThrow(/must not be a symlink/);

    fs.rmSync(sessionPath(dir));
    fs.mkdirSync(sessionPath(dir), { mode: 0o700 });
    expect(() => readSession(dir)).toThrow(/must be a regular file/);

    fs.rmSync(sessionPath(dir), { recursive: true });
    fs.writeFileSync(sessionPath(dir), JSON.stringify(session()), { mode: 0o640 });
    expect(() => readSession(dir)).toThrow(/accessible by group or other users/);

    fs.writeFileSync(cryptoSnapshotPath(dir), Buffer.from([1]), { mode: 0o640 });
    expect(() => loadSnapshotFromDisk(cryptoSnapshotPath(dir))).toThrow(
      /accessible by group or other users/,
    );
  });

  it("rejects a profile directory with a different owner", () => {
    const dir = profileDir();
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("test requires POSIX ownership metadata");
    const original = fs.lstatSync;
    vi.spyOn(fs, "lstatSync").mockImplementation(((target: fs.PathLike) => {
      const stat = original(target);
      if (target === dir) {
        return Object.create(stat, { uid: { value: uid + 1 } }) as fs.Stats;
      }
      return stat;
    }) as typeof fs.lstatSync);

    expect(() => assertSecureProfileDir(dir)).toThrow(/different owner/);
  });
});
