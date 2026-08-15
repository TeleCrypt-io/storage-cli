import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { randomUUID } from "node:crypto";

export interface Session {
  homeserver: string;
  userId: string;
  deviceId: string;
  accessToken: string;
  /** OIDC/MAS device-code grant fields. `oidcTokenEndpoint` is persisted so
   * refresh never needs Node-hostile OIDC discovery after login. */
  refreshToken: string;
  oidcIssuer: string;
  oidcClientId: string;
  oidcTokenEndpoint: string;
}

/**
 * Resolves the profile directory: everything this CLI persists (session,
 * crypto store) lives here. Overridable via TELECRYPT_IO_STORAGE_HOME so
 * tests can give each simulated user/device its own isolated profile.
 * Defaults to ~/.telecrypt-io/storage for normal interactive use.
 */
export function profileDir(): string {
  const home = process.env.TELECRYPT_IO_STORAGE_HOME;
  if (home && home.trim() !== "") return home;
  return path.join(os.homedir(), ".telecrypt-io", "storage");
}

export function sessionPath(dir: string = profileDir()): string {
  return path.join(dir, "session.json");
}

export function cryptoSnapshotPath(dir: string = profileDir()): string {
  return path.join(dir, "crypto.snapshot");
}

function profileSecurityError(target: string, reason: string): Error {
  return new Error(`refusing insecure profile state at ${target}: ${reason}`);
}

function currentUid(): number {
  if (typeof process.getuid !== "function") {
    throw new Error("cannot verify profile ownership on this platform");
  }
  return process.getuid();
}

/** Rejects a profile directory that could expose or redirect persisted tokens
 * and crypto state. Existing state is never repaired implicitly: the owner
 * must inspect it and deliberately restore safe permissions. */
export function assertSecureProfileDir(dir: string = profileDir()): void {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(dir);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  if (stat.isSymbolicLink()) throw profileSecurityError(dir, "profile directory must not be a symlink");
  if (!stat.isDirectory()) throw profileSecurityError(dir, "profile path must be a directory");
  if (stat.uid !== currentUid()) throw profileSecurityError(dir, "profile directory has a different owner");
  if ((stat.mode & 0o077) !== 0) {
    throw profileSecurityError(dir, "profile directory is accessible by group or other users");
  }
}

/** Checks a secret-bearing profile file without following symlinks. */
export function assertSecureProfileFile(filePath: string): void {
  assertSecureProfileDir(path.dirname(filePath));
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return;
    throw err;
  }
  if (stat.isSymbolicLink()) throw profileSecurityError(filePath, "secret file must not be a symlink");
  if (!stat.isFile()) throw profileSecurityError(filePath, "secret file must be a regular file");
  if (stat.uid !== currentUid()) throw profileSecurityError(filePath, "secret file has a different owner");
  if ((stat.mode & 0o077) !== 0) {
    throw profileSecurityError(filePath, "secret file is accessible by group or other users");
  }
}

export function ensureProfileDir(dir: string = profileDir()): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertSecureProfileDir(dir);
}

export function readSession(dir: string = profileDir()): Session | null {
  assertSecureProfileDir(dir);
  const p = sessionPath(dir);
  assertSecureProfileFile(p);
  if (!fs.existsSync(p)) return null;
  const parsed = JSON.parse(fs.readFileSync(p, "utf8")) as Partial<Session>;
  if (
    typeof parsed.homeserver !== "string" ||
    typeof parsed.userId !== "string" ||
    typeof parsed.deviceId !== "string" ||
    typeof parsed.accessToken !== "string" ||
    typeof parsed.refreshToken !== "string" ||
    typeof parsed.oidcIssuer !== "string" ||
    typeof parsed.oidcClientId !== "string" ||
    typeof parsed.oidcTokenEndpoint !== "string"
  ) {
    throw new Error("profile session is not a valid OIDC/MAS session; log in again with --oidc");
  }
  return parsed as Session;
}

export function writeSession(session: Session, dir: string = profileDir()): void {
  ensureProfileDir(dir);
  const destination = sessionPath(dir);
  assertSecureProfileFile(destination);
  const temporary = path.join(dir, `.session-${process.pid}-${randomUUID()}.tmp`);
  try {
    const fd = fs.openSync(temporary, "wx", 0o600);
    try {
      fs.writeFileSync(fd, JSON.stringify(session, null, 2));
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(temporary, destination);
  } finally {
    if (fs.existsSync(temporary)) fs.rmSync(temporary);
  }
  assertSecureProfileFile(destination);
}

/** Clears all local state for this profile (session + crypto store). */
export function clearProfile(dir: string = profileDir()): void {
  assertSecureProfileDir(dir);
  const sp = sessionPath(dir);
  const cp = cryptoSnapshotPath(dir);
  assertSecureProfileFile(sp);
  assertSecureProfileFile(cp);
  if (fs.existsSync(sp)) fs.rmSync(sp);
  if (fs.existsSync(cp)) fs.rmSync(cp);
}
