import fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { randomUUID } from "node:crypto";
import { expectedMatrixServerName } from "./topology.js";
import { withCause } from "./failure.js";

export { expectedMatrixServerName } from "./topology.js";

export interface Session {
  homeserver: string;
  userId: string;
  /** Canonical Matrix server-name binding for the persisted user identity. */
  matrixServerName: string;
  deviceId: string;
  accessToken: string;
  /** OIDC/MAS device-code grant fields. The token endpoint is persisted so
   * refresh never needs discovery after login. */
  oidcIssuer: string;
  refreshToken: string;
  oidcClientId: string;
  oidcTokenEndpoint: string;
  oidcRevocationEndpoint?: string;
}

/** Secret-bearing state retained when a device grant has issued tokens but
 * identity verification or local session persistence has not completed. */
export interface PendingSession {
  homeserver: string;
  deviceId: string;
  accessToken: string;
  oidcIssuer: string;
  refreshToken?: string;
  oidcClientId?: string;
  oidcTokenEndpoint?: string;
  oidcRevocationEndpoint?: string;
  userId?: string;
  matrixServerName?: string;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

function isPersistedOidcUrl(value: unknown): value is string {
  if (
    !isNonEmptyString(value) ||
    value !== value.trim() ||
    /[\s\u0000-\u001f\u007f-\u009f]/u.test(value)
  ) {
    return false;
  }
  try {
    const parsed = new URL(value);
    return (
      (parsed.protocol === "https:" ||
        (parsed.protocol === "http:" &&
          (parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]"))) &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.search === "" &&
      parsed.hash === ""
    );
  } catch {
    return false;
  }
}

function isPersistedOidcBinding(value: unknown, homeserver: unknown, issuer?: string): value is string {
  if (!isPersistedOidcUrl(value) || !isNonEmptyString(homeserver)) return false;
  try {
    const endpoint = new URL(value);
    const home = new URL(homeserver);
    if (endpoint.origin !== home.origin) return false;
    if (issuer === undefined) return true;
    const issuerUrl = new URL(issuer);
    if (endpoint.origin !== issuerUrl.origin) return false;
    if (issuerUrl.pathname === "/") return true;
    const prefix = issuerUrl.pathname.endsWith("/") ? issuerUrl.pathname : `${issuerUrl.pathname}/`;
    return endpoint.pathname === issuerUrl.pathname || endpoint.pathname.startsWith(prefix);
  } catch {
    return false;
  }
}

export const MAX_MATRIX_USER_ID_BYTES = 255;

export function isCanonicalMatrixServerName(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") > MAX_MATRIX_USER_ID_BYTES ||
    value !== value.toLowerCase() ||
    /[\s\u0000-\u001f\u007f-\u009f]/u.test(value)
  ) {
    return false;
  }

  let host = value;
  let port: string | undefined;
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end <= 1) return false;
    host = value.slice(0, end + 1);
    if (value.length > end + 1) {
      if (value[end + 1] !== ":") return false;
      port = value.slice(end + 2);
    }
    try {
      const parsed = new URL(`https://${host}${port === undefined ? "" : `:${port}`}/`);
      if (parsed.hostname !== host || parsed.host !== value) return false;
    } catch {
      return false;
    }
  } else {
    const colon = value.lastIndexOf(":");
    if (colon >= 0) {
      if (value.indexOf(":") !== colon) return false;
      host = value.slice(0, colon);
      port = value.slice(colon + 1);
    }
    if (host.length === 0 || host.length > 253) return false;
    const labels = host.split(".");
    if (
      labels.some(
        (label) =>
          label.length === 0 ||
          label.length > 63 ||
          !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label),
      )
    ) {
      return false;
    }
  }

  if (port !== undefined) {
    if (!/^(?:[1-9][0-9]{0,4})$/u.test(port)) return false;
    const numericPort = Number(port);
    if (numericPort < 1 || numericPort > 65535 || String(numericPort) !== port) return false;
  }
  return true;
}

export function canonicalMatrixServerName(userId: string): string | null {
  const separator = userId.indexOf(":", 1);
  if (separator <= 1 || separator === userId.length - 1) return null;
  return userId.slice(separator + 1);
}

export function isCanonicalMatrixUserId(value: unknown): value is string {
  if (
    typeof value !== "string" ||
    Buffer.byteLength(value, "utf8") > MAX_MATRIX_USER_ID_BYTES ||
    !/^@[a-z0-9._=+\/-]+:[^\s\u0000-\u001f\u007f-\u009f]+$/u.test(value)
  ) {
    return false;
  }
  const serverName = canonicalMatrixServerName(value);
  return serverName !== null && isCanonicalMatrixServerName(serverName);
}

export function isOpaqueValue(value: unknown): value is string {
  return (
    isNonEmptyString(value) &&
    !/[\s\u0000-\u001f\u007f-\u009f]/u.test(value)
  );
}

function isMatrixUserId(value: unknown): value is string {
  return isCanonicalMatrixUserId(value);
}

function isValidSession(value: unknown): value is Session {
  if (!value || typeof value !== "object") return false;
  const session = value as Partial<Session>;
  return (
    isNonEmptyString(session.homeserver) &&
    isMatrixUserId(session.userId) &&
    isOpaqueValue(session.matrixServerName) &&
    session.matrixServerName === canonicalMatrixServerName(session.userId) &&
    expectedMatrixServerName(session.homeserver) === session.matrixServerName &&
    isOpaqueValue(session.deviceId) &&
    isOpaqueValue(session.accessToken) &&
    isPersistedOidcBinding(session.oidcIssuer, session.homeserver) &&
    isOpaqueValue(session.refreshToken) &&
    isOpaqueValue(session.oidcClientId) &&
    isPersistedOidcBinding(session.oidcTokenEndpoint, session.homeserver, session.oidcIssuer) &&
    (session.oidcRevocationEndpoint === undefined ||
      isPersistedOidcBinding(session.oidcRevocationEndpoint, session.homeserver, session.oidcIssuer))
  );
}

export function isValidPendingSession(value: unknown): value is PendingSession {
  if (!value || typeof value !== "object") return false;
  const pending = value as Partial<PendingSession>;
  return (
    isNonEmptyString(pending.homeserver) &&
    isOpaqueValue(pending.deviceId) &&
    isOpaqueValue(pending.accessToken) &&
    isPersistedOidcBinding(pending.oidcIssuer, pending.homeserver) &&
    (pending.refreshToken === undefined ||
      (isOpaqueValue(pending.refreshToken) &&
        isOpaqueValue(pending.oidcClientId) &&
        isPersistedOidcBinding(pending.oidcTokenEndpoint, pending.homeserver, pending.oidcIssuer))) &&
    (pending.oidcClientId === undefined || isOpaqueValue(pending.oidcClientId)) &&
    (pending.oidcTokenEndpoint === undefined ||
      isPersistedOidcBinding(pending.oidcTokenEndpoint, pending.homeserver, pending.oidcIssuer)) &&
    (pending.oidcRevocationEndpoint === undefined ||
      isPersistedOidcBinding(pending.oidcRevocationEndpoint, pending.homeserver, pending.oidcIssuer)) &&
    isCanonicalMatrixServerName(pending.matrixServerName) &&
    expectedMatrixServerName(pending.homeserver) === pending.matrixServerName &&
    (pending.userId === undefined ||
      (isMatrixUserId(pending.userId) &&
        isOpaqueValue(pending.matrixServerName) &&
        pending.matrixServerName === canonicalMatrixServerName(pending.userId)))
  );
}

/**
 * Resolves the profile directory: everything this CLI persists (session,
 * crypto store) lives here. Overridable via TELECRYPT_IO_STORAGE_HOME so
 * tests can give each simulated user/device its own isolated profile.
 * Defaults to ~/.telecrypt-io/storage for normal interactive use.
 */
export function profileDir(): string {
  const home = process.env.TELECRYPT_IO_STORAGE_HOME;
  if (home !== undefined) {
    if (
      home.length === 0 ||
      home !== home.trim() ||
      !path.isAbsolute(home) ||
      path.parse(path.resolve(home)).root === path.resolve(home)
    ) {
      throw new Error("TELECRYPT_IO_STORAGE_HOME must be a non-root absolute profile path");
    }
    return path.resolve(home);
  }
  return path.join(os.homedir(), ".telecrypt-io", "storage");
}

export function sessionPath(dir: string = profileDir()): string {
  return path.join(dir, "session.json");
}

export function pendingSessionPath(dir: string = profileDir()): string {
  return path.join(dir, "login-pending.json");
}

export function cryptoSnapshotPath(dir: string = profileDir()): string {
  return path.join(dir, "crypto.snapshot");
}

export function logoutMarkerPath(dir: string = profileDir()): string {
  return path.join(dir, "logout-complete");
}

const profileLockPath = (dir: string): string => path.join(dir, ".profile.lock");
function serializeSession(value: Session | PendingSession, label: string): string {
  const serialized = JSON.stringify(value, null, 2);
  if (typeof serialized !== "string") {
    throw new Error(`${label} is not serializable`);
  }
  return serialized;
}

function profilePath(directory: string, name: string): string {
  if (!name || name === "." || name === ".." || name.includes("/")) {
    throw new Error("profile file name is invalid");
  }
  return path.join(directory, name);
}

/** Restores a quarantined lock only when the destination is still absent.
 * `rename(2)` replaces an existing destination, which could overwrite a lock
 * acquired by another process during stale-lock recovery. A same-directory
 * hard link gives us atomic create-if-absent semantics without a dependency. */
function restoreLockWithoutReplacement(directory: string, sourceName: string, destinationName: string): void {
  const source = profilePath(directory, sourceName);
  const destination = profilePath(directory, destinationName);
  try {
    fs.linkSync(source, destination);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      // A new owner won the race. Preserve that lock and discard only our
      // quarantined stale copy.
      fs.rmSync(source);
      return;
    }
    throw error;
  }
  fs.rmSync(source);
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

/** Keep the profile directory private; do not silently change existing modes. */
export function assertSecureProfileDir(dir: string = profileDir()): void {
  const resolved = path.resolve(dir);
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(resolved);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (stat.isSymbolicLink()) throw profileSecurityError(dir, "profile directory must not be a symlink");
  if (!stat.isDirectory()) throw profileSecurityError(dir, "profile path is not a directory");
  if (stat.uid !== currentUid()) throw profileSecurityError(dir, "profile directory has a different owner");
  if ((stat.mode & 0o077) !== 0) {
    throw profileSecurityError(dir, "profile directory is accessible by group or other users");
  }
}

export function ensureProfileDir(dir: string = profileDir()): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  assertSecureProfileDir(dir);
}

export interface ProfileLock {
  /** Resolved directory holding the lock file. */
  readonly directory: string;
  release(): void;
}

export function throwWithLockReleaseFailure(lock: ProfileLock, primary: unknown): never {
  try {
    lock.release();
  } catch (releaseError) {
    throw new AggregateError(
      [primary, releaseError],
      "operation and profile lock cleanup failed",
    );
  }
  throw primary;
}

/**
 * Holds an exclusive lock for the lifetime of a storage command.  The lock is
 * a private file in the already owner-checked profile directory.  A dead
 * process's lock is recoverable; a live owner's lock is never stolen.
 */
export function acquireProfileLock(dir: string = profileDir()): ProfileLock {
  ensureProfileDir(dir);
  const directory = path.resolve(dir);
  const lockPath = profilePath(directory, ".profile.lock");
  const token = randomUUID();
  const contents = JSON.stringify({ pid: process.pid, token });
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW;

  const lock = (): ProfileLock => {
    let released = false;
    let quarantine: string | undefined;
    return {
      directory,
      release: () => {
        if (released) return;
        if (!quarantine) {
          quarantine = `${lockPath}.${randomUUID()}.release`;
          try {
            fs.renameSync(lockPath, quarantine);
          } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "ENOENT") {
              quarantine = undefined;
              released = true;
              return;
            }
            throw error;
          }
        }
        const owner = readPrivateFileAt(directory, path.basename(quarantine))?.toString("utf8");
        let ownsEntry = false;
        try {
          const parsed = owner ? (JSON.parse(owner) as { pid?: unknown; token?: unknown }) : undefined;
          ownsEntry = parsed?.pid === process.pid && parsed.token === token;
        } catch {
          ownsEntry = false;
        }
        if (ownsEntry) fs.rmSync(quarantine);
        else restoreLockWithoutReplacement(directory, path.basename(quarantine), ".profile.lock");
        quarantine = undefined;
        released = true;
      },
    };
  };

  for (;;) {
    try {
      const fd = fs.openSync(lockPath, flags, 0o600);
      try {
        fs.writeFileSync(fd, contents);
      } catch (error) {
        fs.closeSync(fd);
        fs.rmSync(lockPath, { force: true });
        throw error;
      }
      try {
        fs.closeSync(fd);
      } catch (error) {
        fs.rmSync(lockPath, { force: true });
        throw error;
      }
      return lock();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }

    const owner = readPrivateFileAt(directory, ".profile.lock");
    if (!owner) continue;
    let pid: unknown;
    try {
      pid = (JSON.parse(owner.toString("utf8")) as { pid?: unknown }).pid;
    } catch {
      throw new Error("profile lock is invalid; inspect it before retrying");
    }
    if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) {
      throw new Error("profile lock is invalid; inspect it before retrying");
    }
    try {
      process.kill(pid, 0);
      throw new Error("profile is busy; retry after the other storage command exits");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
    }

    // Move the stale entry out of the way, then compare its contents before
    // deleting it so concurrent recoveries never remove a replacement lock.
    const quarantine = `${lockPath}.${randomUUID()}.stale`;
    try {
      fs.renameSync(lockPath, quarantine);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    try {
      const movedOwner = readPrivateFileAt(directory, path.basename(quarantine));
      if (!movedOwner || !movedOwner.equals(owner)) {
        restoreLockWithoutReplacement(directory, path.basename(quarantine), ".profile.lock");
        continue;
      }
      fs.rmSync(quarantine);
    } catch (error) {
      try {
        if (fs.existsSync(quarantine)) {
          restoreLockWithoutReplacement(directory, path.basename(quarantine), ".profile.lock");
        }
      } catch {
        // The original failure is more useful; the quarantine path remains for inspection.
      }
      throw error;
    }
  }
}

function profileDirectoryFor(dir: string, heldLock?: ProfileLock): string {
  const resolved = path.resolve(dir);
  if (heldLock) {
    if (heldLock.directory !== resolved) {
      throw new Error("profile lock does not match the requested profile directory");
    }
    return resolved;
  }
  assertSecureProfileDir(resolved);
  return resolved;
}

function readPrivateFileAt(directory: string, name: string): Buffer | null {
  const filePath = profilePath(directory, name);
  let fd: number;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw profileSecurityError(filePath, "secret file must be a regular file");
    if (stat.uid !== currentUid()) throw profileSecurityError(filePath, "secret file has a different owner");
    if ((stat.mode & 0o077) !== 0) {
      throw profileSecurityError(filePath, "secret file is accessible by group or other users");
    }
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export function readPrivateFile(filePath: string, heldLock?: ProfileLock): Buffer | null {
  const directory = path.dirname(filePath);
  return readPrivateFileAt(profileDirectoryFor(directory, heldLock), path.basename(filePath));
}

export function readSession(
  dir: string = profileDir(),
  heldLock?: ProfileLock,
): Session | null {
  const p = sessionPath(dir);
  const bytes = readPrivateFile(p, heldLock);
  if (!bytes) return null;
  let parsed: Partial<Session>;
  try {
    parsed = JSON.parse(bytes.toString("utf8")) as Partial<Session>;
  } catch (error) {
    throw withCause(new Error("profile session is not valid JSON; log in again"), error);
  }
  if (!isValidSession(parsed)) {
    throw new Error("profile session is not a valid OIDC/MAS session; log in again");
  }
  return parsed;
}

export function readPendingSession(
  dir: string = profileDir(),
  heldLock?: ProfileLock,
): PendingSession | null {
  const bytes = readPrivateFile(pendingSessionPath(dir), heldLock);
  if (!bytes) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch (error) {
    throw withCause(new Error("pending login state is not valid JSON; inspect it before retrying"), error);
  }
  if (!isValidPendingSession(parsed)) {
    throw new Error("pending login state is invalid; inspect it before retrying");
  }
  return parsed;
}

/** Refuses a new login when any previous profile state remains. The caller
 * must already hold the profile lock; the lock file itself is expected. */
export function assertFreshProfileUnlocked(dir: string = profileDir(), heldLock?: ProfileLock): void {
  if (!heldLock) ensureProfileDir(dir);
  const directory = profileDirectoryFor(dir, heldLock);
  let entries = fs.readdirSync(directory);
  entries = entries.filter((entry) => entry !== path.basename(profileLockPath(dir)));
  if (entries.length > 0) {
    throw new Error("profile is not empty; run `telecrypt-io storage logout` before logging in again");
  }
}

/** Atomically replaces a private profile file without exposing partial state. */
export function writePrivateFile(
  destination: string,
  contents: string | NodeJS.ArrayBufferView,
  heldLock?: ProfileLock,
): void {
  const parent = path.dirname(destination);
  if (!heldLock) ensureProfileDir(parent);
  const directory = profileDirectoryFor(parent, heldLock);
  const name = path.basename(destination);
  const target = profilePath(directory, name);
  const temporary = profilePath(directory, `.${name}-${process.pid}-${randomUUID()}.tmp`);

  try {
    const fd = fs.openSync(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600,
    );
    try {
      fs.writeFileSync(fd, contents);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(temporary, target);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

export function writeSession(
  session: Session,
  dir: string = profileDir(),
): void {
  const lock = acquireProfileLock(dir);
  try {
    writeSessionUnlocked(session, dir, lock);
  } catch (error) {
    throwWithLockReleaseFailure(lock, error);
  }
  lock.release();
}

/** Writes session state while the caller already holds the profile lock. */
export function writeSessionUnlocked(
  session: Session,
  dir: string = profileDir(),
  heldLock?: ProfileLock,
): void {
  if (!isValidSession(session)) {
    throw new Error("profile session is not a valid OIDC/MAS session; log in again");
  }
  writePrivateFile(sessionPath(dir), serializeSession(session, "profile session"), heldLock);
}

export function writePendingSessionUnlocked(
  pending: PendingSession,
  dir: string = profileDir(),
  heldLock?: ProfileLock,
): void {
  if (!isValidPendingSession(pending)) {
    throw new Error("pending login state is invalid; refusing to persist credentials");
  }
  writePrivateFile(
    pendingSessionPath(dir),
    serializeSession(pending, "pending login state"),
    heldLock,
  );
}

export function writeLogoutMarkerUnlocked(dir: string = profileDir(), heldLock?: ProfileLock): void {
  writePrivateFile(logoutMarkerPath(dir), "server-revoked\n", heldLock);
}

export function hasLogoutMarker(dir: string = profileDir(), heldLock?: ProfileLock): boolean {
  const marker = readPrivateFile(logoutMarkerPath(dir), heldLock);
  if (!marker) return false;
  if (marker.toString("utf8") !== "server-revoked\n") {
    throw new Error("logout cleanup marker is invalid; inspect the profile before retrying");
  }
  return true;
}

/** Clears all local state for this profile (session + crypto store). */
export function clearProfileUnlocked(
  dir: string = profileDir(),
  heldLock?: ProfileLock,
): void {
  const directory = profileDirectoryFor(dir, heldLock);
  const marker = path.basename(logoutMarkerPath(dir));
  const files = [
    path.basename(sessionPath(dir)),
    path.basename(pendingSessionPath(dir)),
    path.basename(cryptoSnapshotPath(dir)),
  ];
  for (const file of [...files, marker]) {
    try {
      if (!fs.lstatSync(profilePath(directory, file)).isFile()) {
        throw new Error("profile cleanup is incomplete; inspect remaining private state before retrying");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
  for (const file of files) {
    fs.rmSync(profilePath(directory, file), { force: true });
  }
  const remaining = fs.readdirSync(directory)
    .filter((entry) => entry !== path.basename(profileLockPath(dir)))
    .filter((entry) => entry !== marker);
  if (remaining.length > 0) {
    throw new Error("profile cleanup is incomplete; inspect remaining private state before retrying");
  }
  fs.rmSync(profilePath(directory, marker), { force: true });
}
