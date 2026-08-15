import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

export interface Session {
  homeserver: string;
  userId: string;
  deviceId: string;
  accessToken: string;
  /**
   * Set by `storage login` (device-code grant against MAS; see src/oidc.ts).
   * `oidcTokenEndpoint` is persisted
   * directly (rather than re-discovered from `oidcIssuer` on every command)
   * so reusing/refreshing the session never needs OIDC discovery again —
   * discovery is Node-hostile (see src/oidcWindowPolyfill.ts) and this
   * avoids needing it more than once, at login time.
   */
  refreshToken?: string;
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

export function ensureProfileDir(dir: string = profileDir()): void {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  validatePrivatePath(dir, "profile directory", "directory");
}

function validatePrivatePath(
  target: string,
  label: string,
  expected: "file" | "directory",
): void {
  const stat = fs.lstatSync(target);
  const hasExpectedType = expected === "file" ? stat.isFile() : stat.isDirectory();
  if (stat.isSymbolicLink() || !hasExpectedType) {
    throw new Error(`${label} must be a regular ${expected} and not a symbolic link: ${target}`);
  }
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error(`${label} is not owned by the current user: ${target}`);
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(`${label} permissions are too broad; remove all group/other access: ${target}`);
  }
}

export function validatePrivateFile(target: string, label: string): void {
  validatePrivatePath(target, label, "file");
}

export function writePrivateFileAtomic(target: string, data: string | NodeJS.ArrayBufferView): void {
  const dir = path.dirname(target);
  ensureProfileDir(dir);
  if (fs.existsSync(target)) validatePrivateFile(target, path.basename(target));

  const temp = path.join(dir, `.${path.basename(target)}.${process.pid}.${Date.now()}.tmp`);
  try {
    fs.writeFileSync(temp, data, { flag: "wx", mode: 0o600 });
    fs.renameSync(temp, target);
  } finally {
    if (fs.existsSync(temp)) fs.rmSync(temp);
  }
}

export function readSession(dir: string = profileDir()): Session | null {
  const p = sessionPath(dir);
  if (!fs.existsSync(p)) return null;
  ensureProfileDir(dir);
  validatePrivateFile(p, "session file");
  const raw = fs.readFileSync(p, "utf8");
  const parsed = JSON.parse(raw) as Partial<Session>;
  const required = [
    parsed.homeserver,
    parsed.userId,
    parsed.deviceId,
    parsed.accessToken,
    parsed.oidcIssuer,
    parsed.oidcClientId,
    parsed.oidcTokenEndpoint,
  ];
  if (!required.every((value) => typeof value === "string" && value !== "")) {
    throw new Error("session file is invalid or predates OAuth-only login; log in again through MAS");
  }
  return parsed as Session;
}

export function writeSession(session: Session, dir: string = profileDir()): void {
  ensureProfileDir(dir);
  writePrivateFileAtomic(sessionPath(dir), JSON.stringify(session, null, 2));
}

/** Clears all local state for this profile (session + crypto store). */
export function clearProfile(dir: string = profileDir()): void {
  const sp = sessionPath(dir);
  const cp = cryptoSnapshotPath(dir);
  if (fs.existsSync(sp)) fs.rmSync(sp);
  if (fs.existsSync(cp)) fs.rmSync(cp);
}
