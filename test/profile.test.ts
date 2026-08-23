import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
  assertSecureProfileDir,
  cryptoSnapshotPath,
  readSession,
  sessionPath,
  writeSession,
} from "../src/profile.js";
import { loadSnapshotFromDisk, saveSnapshotToDisk } from "../src/cryptoSnapshot.js";

const dirs: string[] = [];

function profileDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-profile-test-"));
  fs.chmodSync(dir, 0o700);
  dirs.push(dir);
  return dir;
}

function session() {
  return {
    homeserver: "https://backend.example.test",
    userId: "@alice:example.test",
    deviceId: "DEVICE",
    accessToken: "access-token",
    refreshToken: "refresh-token",
    oidcClientId: "client",
    oidcTokenEndpoint: "https://auth.example.test/token",
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("secret-bearing CLI profile state", () => {
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
    writeSession({ ...session(), refreshToken: "" }, dir);
    expect(() => readSession(dir)).toThrow(/not a valid OIDC\/MAS session/);
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
