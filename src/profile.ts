import fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { createHash, randomUUID } from "node:crypto";

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
    Buffer.byteLength(value, "utf8") > 2048 ||
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

const MAX_SESSION_VALUE_BYTES = 16 * 1024;
export const MAX_MATRIX_USER_ID_BYTES = 255;

const TELECRYPT_PRODUCTION_BACKEND = "backend.telecrypt.io";
const TELECRYPT_SUFFIX = ".telecrypt.io";
const TELECRYPT_PREPRODUCTION_PREFIX = "backend.";
const MAX_SERVER_LABEL_BYTES = 40;

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

function isLoopbackHostname(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}

/** Returns the independently trusted Matrix server name for the supported
 * TeleCrypt backend topology. The local disposable fixture is deliberately
 * bound to one fixed loopback identity, so callers cannot override it. */
export function expectedMatrixServerName(homeserver: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(homeserver);
  } catch {
    return null;
  }
  if (
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.pathname !== "/"
  ) {
    return null;
  }
  if (homeserver !== parsed.origin && homeserver !== `${parsed.origin}/`) return null;
  if (isLoopbackHostname(parsed.hostname)) return parsed.protocol === "http:" ? "example.test" : null;
  if (parsed.protocol !== "https:" || parsed.port !== "") return null;
  if (parsed.hostname === TELECRYPT_PRODUCTION_BACKEND) return "telecrypt.io";
  if (
    parsed.hostname.startsWith(TELECRYPT_PREPRODUCTION_PREFIX) &&
    parsed.hostname.endsWith(TELECRYPT_SUFFIX)
  ) {
    const serverName = parsed.hostname.slice(TELECRYPT_PREPRODUCTION_PREFIX.length);
    const label = serverName.slice(0, -TELECRYPT_SUFFIX.length);
    if (
      Buffer.byteLength(label, "utf8") >= 1 &&
      Buffer.byteLength(label, "utf8") <= MAX_SERVER_LABEL_BYTES &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label)
    ) {
      return serverName;
    }
  }
  return null;
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

export function isBoundedOpaqueValue(value: unknown, maxBytes = MAX_SESSION_VALUE_BYTES): value is string {
  return (
    isNonEmptyString(value) &&
    Buffer.byteLength(value, "utf8") <= maxBytes &&
    !/[\s\u0000-\u001f\u007f-\u009f]/u.test(value)
  );
}

function isMatrixUserId(value: unknown): value is string {
  return isBoundedOpaqueValue(value, MAX_MATRIX_USER_ID_BYTES) && isCanonicalMatrixUserId(value);
}

function isValidSession(value: unknown): value is Session {
  if (!value || typeof value !== "object") return false;
  const session = value as Partial<Session>;
  return (
    isNonEmptyString(session.homeserver) &&
    isMatrixUserId(session.userId) &&
    isBoundedOpaqueValue(session.matrixServerName, MAX_MATRIX_USER_ID_BYTES) &&
    session.matrixServerName === canonicalMatrixServerName(session.userId) &&
    expectedMatrixServerName(session.homeserver) === session.matrixServerName &&
    isBoundedOpaqueValue(session.deviceId) &&
    isBoundedOpaqueValue(session.accessToken) &&
    isPersistedOidcBinding(session.oidcIssuer, session.homeserver) &&
    isBoundedOpaqueValue(session.refreshToken) &&
    isBoundedOpaqueValue(session.oidcClientId) &&
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
    isBoundedOpaqueValue(pending.deviceId) &&
    isBoundedOpaqueValue(pending.accessToken) &&
    isPersistedOidcBinding(pending.oidcIssuer, pending.homeserver) &&
    (pending.refreshToken === undefined ||
      (isBoundedOpaqueValue(pending.refreshToken) &&
        isBoundedOpaqueValue(pending.oidcClientId) &&
        isPersistedOidcBinding(pending.oidcTokenEndpoint, pending.homeserver, pending.oidcIssuer))) &&
    (pending.oidcClientId === undefined || isBoundedOpaqueValue(pending.oidcClientId)) &&
    (pending.oidcTokenEndpoint === undefined ||
      isPersistedOidcBinding(pending.oidcTokenEndpoint, pending.homeserver, pending.oidcIssuer)) &&
    (pending.oidcRevocationEndpoint === undefined ||
      isPersistedOidcBinding(pending.oidcRevocationEndpoint, pending.homeserver, pending.oidcIssuer)) &&
    isCanonicalMatrixServerName(pending.matrixServerName) &&
    expectedMatrixServerName(pending.homeserver) === pending.matrixServerName &&
    (pending.userId === undefined ||
      (isMatrixUserId(pending.userId) &&
        isBoundedOpaqueValue(pending.matrixServerName, MAX_MATRIX_USER_ID_BYTES) &&
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
      /[\u0000-\u001f\u007f-\u009f]/u.test(home) ||
      !path.isAbsolute(home) ||
      path.resolve(home) !== home ||
      path.parse(home).root === home
    ) {
      throw new Error("TELECRYPT_IO_STORAGE_HOME must be a canonical absolute profile path");
    }
    return home;
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
export const MAX_SESSION_BYTES = 16 * 1024;
/** Private local profile and crypto snapshot ceiling; media has its own 128 MiB limit. */
export const MAX_PRIVATE_FILE_BYTES = 64 * 1024 * 1024;
export const MAX_MEDIA_FILE_BYTES = 128 * 1024 * 1024;

function serializeBoundedSession(value: Session | PendingSession, label: string): string {
  const serialized = JSON.stringify(value, null, 2);
  if (typeof serialized !== "string") {
    throw new Error(`${label} is not serializable`);
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_SESSION_BYTES) {
    throw new Error(`${label} exceeds maximum size of ${MAX_SESSION_BYTES} bytes`);
  }
  return serialized;
}

const PROFILE_DIRECTORY_FLAGS = fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW;
const PROFILE_PROC_FD_ROOT = "/proc/self/fd";

function openSecureProfileDirectory(dir: string): number {
  if (process.platform !== "linux" || !fs.existsSync(PROFILE_PROC_FD_ROOT)) {
    throw new Error("secure profile state requires Linux /proc/self/fd support");
  }
  const resolved = path.resolve(dir);
  if (path.parse(resolved).root !== "/") throw new Error("secure profile path must be absolute");
  let fd = fs.openSync("/", PROFILE_DIRECTORY_FLAGS);
  try {
    const components = resolved.split("/").filter(Boolean);
    for (const [index, component] of components.entries()) {
      const next = fs.openSync(path.join(PROFILE_PROC_FD_ROOT, String(fd), component), PROFILE_DIRECTORY_FLAGS);
      fs.closeSync(fd);
      fd = next;
      const stat = fs.fstatSync(fd);
      const final = index === components.length - 1;
      if (!stat.isDirectory()) throw profileSecurityError(dir, "profile path component is not a directory");
      if (final) {
        if (stat.uid !== currentUid()) throw profileSecurityError(dir, "profile directory has a different owner");
        if ((stat.mode & 0o077) !== 0) {
          throw profileSecurityError(dir, "profile directory is accessible by group or other users");
        }
      } else {
        const ownedByTrustedUser = stat.uid === 0 || stat.uid === currentUid();
        // A standard 1777 temporary directory is safe for a private child:
        // the sticky bit prevents another user from replacing entries they do
        // not own.  Do not require a particular owner for this contract; some
        // containerized Linux environments deliberately map /tmp to nobody.
        const safelyShared = (stat.mode & 0o1000) !== 0 && (stat.mode & 0o002) !== 0;
        if ((!ownedByTrustedUser && !safelyShared) || ((stat.mode & 0o022) !== 0 && !safelyShared)) {
          throw profileSecurityError(dir, "profile path has an untrusted writable ancestor");
        }
      }
    }
    if (components.length === 0) throw profileSecurityError(dir, "the filesystem root cannot be a profile directory");
    return fd;
  } catch (error) {
    try {
      fs.closeSync(fd);
    } catch {
      // Preserve the fail-closed error.
    }
    throw error;
  }
}

function anchoredProfilePath(directoryFd: number, name: string): string {
  if (!name || name === "." || name === ".." || name.includes("/")) {
    throw new Error("profile file name is invalid");
  }
  return path.join(PROFILE_PROC_FD_ROOT, String(directoryFd), name);
}

function processStartIdentity(pid: number): string | undefined {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    const endOfCommand = stat.lastIndexOf(")");
    if (endOfCommand < 0) return undefined;
    const fields = stat.slice(endOfCommand + 2).trim().split(/\s+/u);
    return fields[19];
  } catch {
    return undefined;
  }
}

const currentProcessStartIdentity = processStartIdentity(process.pid);

/** Restores a quarantined lock only when the destination is still absent.
 * `rename(2)` replaces an existing destination, which could overwrite a lock
 * acquired by another process during stale-lock recovery. A same-directory
 * hard link gives us atomic create-if-absent semantics without a dependency. */
function restoreLockWithoutReplacement(directoryFd: number, sourceName: string, destinationName: string): void {
  const source = anchoredProfilePath(directoryFd, sourceName);
  const destination = anchoredProfilePath(directoryFd, destinationName);
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

/** Rejects a profile directory that could expose or redirect persisted tokens
 * and crypto state. Existing state is never repaired implicitly: the owner
 * must inspect it and deliberately restore safe permissions. */
export function assertSecureProfileDir(dir: string = profileDir()): void {
  let ancestor = path.dirname(path.resolve(dir));
  while (true) {
    try {
      if (fs.lstatSync(ancestor).isSymbolicLink()) {
        throw profileSecurityError(dir, "profile path must not contain symlink components");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const parent = path.dirname(ancestor);
    if (parent === ancestor) break;
    ancestor = parent;
  }
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

export interface ProfileLock {
  /** Resolved directory bound to `directoryFd` for the lock lifetime. */
  readonly directory: string;
  /** Retained, verified directory descriptor used to anchor every state operation. */
  readonly directoryFd: number;
  release(): void;
}

/**
 * Holds an exclusive lock for the lifetime of a storage command.  The lock is
 * a private file in the already owner-checked profile directory.  A dead
 * process's lock is recoverable; a live owner's lock is never stolen.
 */
export function acquireProfileLock(dir: string = profileDir()): ProfileLock {
  ensureProfileDir(dir);
  if (currentProcessStartIdentity === undefined) {
    throw new Error("cannot establish the current process identity for profile locking");
  }
  const resolvedDirectory = path.resolve(dir);
  const directoryFd = openSecureProfileDirectory(dir);
  const lockPath = anchoredProfilePath(directoryFd, ".profile.lock");
  const token = randomUUID();
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW;
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      const fd = fs.openSync(lockPath, flags, 0o600);
      try {
        fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, token, startTime: currentProcessStartIdentity }));
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      let released = false;
      let quarantine: string | undefined;
      return {
        directory: resolvedDirectory,
        directoryFd,
        release: () => {
          if (released) return;
          try {
            if (!quarantine) {
              quarantine = `${lockPath}.${randomUUID()}.release`;
              try {
                fs.renameSync(lockPath, quarantine);
              } catch (error) {
                if ((error as NodeJS.ErrnoException).code === "ENOENT") {
                  released = true;
                  quarantine = undefined;
                  fs.closeSync(directoryFd);
                  return;
                }
                throw error;
              }
            }
            if (!quarantine) throw new Error("profile lock quarantine path is unavailable");
            const owner = readPrivateFileAt(directoryFd, path.basename(quarantine), 1024)?.toString("utf8");
            let ownsEntry = false;
            try {
              const parsed = owner ? (JSON.parse(owner) as { pid?: unknown; token?: unknown }) : undefined;
              ownsEntry = parsed?.pid === process.pid && parsed.token === token;
            } catch {
              ownsEntry = false;
            }
            if (ownsEntry) {
              fs.rmSync(quarantine);
            } else {
              restoreLockWithoutReplacement(directoryFd, path.basename(quarantine), ".profile.lock");
            }
            released = true;
            quarantine = undefined;
            fs.closeSync(directoryFd);
          } catch {
            // Keep the quarantine path for a same-process retry and surface
            // the failure instead of silently leaving an orphaned profile
            // entry that makes later commands fail for an unrelated reason.
            throw new Error(
              `profile lock cleanup failed; inspect ${quarantine ?? lockPath} and retry`,
            );
          }
        },
      };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
        fs.closeSync(directoryFd);
        throw error;
      }
      const owner = readPrivateFileAt(directoryFd, ".profile.lock", 1024);
      if (!owner) continue;
      let pid: unknown;
      let startTime: unknown;
      try {
        const parsed = owner ? (JSON.parse(owner.toString("utf8")) as { pid?: unknown; startTime?: unknown }) : undefined;
        pid = parsed?.pid;
        startTime = parsed?.startTime;
      } catch {
        fs.closeSync(directoryFd);
        throw new Error("profile lock is invalid; inspect it before retrying");
      }
      if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 0) {
        fs.closeSync(directoryFd);
        throw new Error("profile lock is invalid; inspect it before retrying");
      }
      let ownerLive = false;
      try {
        process.kill(pid, 0);
        const actualStart = processStartIdentity(pid);
        if (typeof startTime !== "string") {
          ownerLive = true;
        } else if (actualStart === startTime) {
          ownerLive = true;
        } else if (actualStart === undefined) {
          // `/proc` can disappear between the liveness probe and identity
          // read. Probe once more and fail closed if the PID is live again.
          try {
            process.kill(pid, 0);
            ownerLive = true;
          } catch (secondProbeError) {
            if ((secondProbeError as NodeJS.ErrnoException).code !== "ESRCH") throw secondProbeError;
          }
        }
      } catch (probeError) {
        if ((probeError as NodeJS.ErrnoException).code !== "ESRCH") {
          fs.closeSync(directoryFd);
          throw probeError;
        }
      }
      if (ownerLive) {
        fs.closeSync(directoryFd);
        throw new Error("profile is busy; retry after the other storage command exits");
      }
      // Node has no portable compare-and-unlink primitive. Atomically move
      // the pathname to a unique quarantine entry, then compare the bytes
      // that were moved before deleting that entry. A competing recovery
      // either wins this rename (and this attempt retries) or leaves a live
      // replacement at the original pathname untouched.
      const quarantine = `${lockPath}.${randomUUID()}.stale`;
      try {
        fs.renameSync(lockPath, quarantine);
      } catch (renameError) {
        if ((renameError as NodeJS.ErrnoException).code === "ENOENT") continue;
        fs.closeSync(directoryFd);
        throw renameError;
      }
      try {
        const movedOwner = readPrivateFileAt(directoryFd, path.basename(quarantine), 1024);
        if (!movedOwner || !owner || !movedOwner.equals(owner)) {
          // The moved entry is not the stale bytes we inspected. Restore it
          // only while the lock pathname is still free and retry; never
          // unlink a replacement owned by another process.
          restoreLockWithoutReplacement(directoryFd, path.basename(quarantine), ".profile.lock");
          continue;
        }
        if (typeof startTime === "string" && processStartIdentity(pid) === startTime) {
          restoreLockWithoutReplacement(directoryFd, path.basename(quarantine), ".profile.lock");
          fs.closeSync(directoryFd);
          throw new Error("profile is busy; retry after the other storage command exits");
        }
        fs.rmSync(quarantine);
      } catch (quarantineError) {
        try {
          if (fs.existsSync(quarantine)) {
            restoreLockWithoutReplacement(directoryFd, path.basename(quarantine), ".profile.lock");
          }
        } catch {
          // Preserve the original failure; the private profile remains
          // inspectable for a later explicit recovery.
        }
        fs.closeSync(directoryFd);
        throw quarantineError;
      }
    }
  }
  fs.closeSync(directoryFd);
  throw new Error("profile is busy; retry after the other storage command exits");
}

export async function withProfileLock<T>(dir: string, operation: () => Promise<T>): Promise<T> {
  const lock = acquireProfileLock(dir);
  try {
    return await operation();
  } finally {
    lock.release();
  }
}

function directoryHandleFor(
  dir: string,
  heldLock?: ProfileLock,
): { fd: number; owned: boolean } {
  const resolved = path.resolve(dir);
  if (heldLock) {
    if (heldLock.directory !== resolved) {
      throw new Error("profile lock does not match the requested profile directory");
    }
    // Verify the retained handle remains a private directory owned by us.
    const stat = fs.fstatSync(heldLock.directoryFd);
    if (!stat.isDirectory() || stat.uid !== currentUid() || (stat.mode & 0o077) !== 0) {
      throw profileSecurityError(dir, "retained profile directory handle is no longer safe");
    }
    return { fd: heldLock.directoryFd, owned: false };
  }
  return { fd: openSecureProfileDirectory(resolved), owned: true };
}

function readPrivateFileAt(directoryFd: number, name: string, maxBytes: number): Buffer | null {
  const filePath = anchoredProfilePath(directoryFd, name);
  let observed: fs.Stats;
  try {
    observed = fs.lstatSync(filePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  if (observed.isSymbolicLink()) throw profileSecurityError(filePath, "secret file must not be a symlink");
  if (!observed.isFile()) throw profileSecurityError(filePath, "secret file must be a regular file");
  if (observed.uid !== currentUid()) throw profileSecurityError(filePath, "secret file has a different owner");
  if ((observed.mode & 0o077) !== 0) {
    throw profileSecurityError(filePath, "secret file is accessible by group or other users");
  }
  let fd: number;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (stat.dev !== observed.dev || stat.ino !== observed.ino) {
      throw profileSecurityError(filePath, "secret file changed while it was being opened");
    }
    if (!stat.isFile()) throw profileSecurityError(filePath, "secret file changed while it was being opened");
    if (stat.uid !== currentUid()) throw profileSecurityError(filePath, "secret file changed owner while it was being opened");
    if ((stat.mode & 0o077) !== 0) {
      throw profileSecurityError(filePath, "secret file became accessible by group or other users while it was being opened");
    }
    if (stat.size > maxBytes) throw new Error(`profile file exceeds maximum size of ${maxBytes} bytes`);
    const out = Buffer.alloc(stat.size);
    let offset = 0;
    while (offset < out.length) {
      const read = fs.readSync(fd, out, offset, out.length - offset, null);
      if (read === 0) break;
      offset += read;
    }
    if (offset !== out.length) throw new Error("profile file changed while it was being read");
    const digest = createHash("sha256").update(out).digest();
    const verifyHash = createHash("sha256");
    const verifyBuffer = Buffer.alloc(Math.min(Math.max(stat.size, 1), 64 * 1024));
    let position = 0;
    while (position < stat.size) {
      const read = fs.readSync(fd, verifyBuffer, 0, Math.min(verifyBuffer.length, stat.size - position), position);
      if (read === 0) throw new Error("profile file changed while it was being read");
      verifyHash.update(verifyBuffer.subarray(0, read));
      position += read;
    }
    const final = fs.fstatSync(fd);
    if (
      final.dev !== observed.dev ||
      final.ino !== observed.ino ||
      final.size !== stat.size ||
      final.mode !== stat.mode ||
      final.mtimeMs !== stat.mtimeMs ||
      final.ctimeMs !== stat.ctimeMs ||
      !digest.equals(verifyHash.digest())
    ) {
      throw new Error("profile file changed while it was being read");
    }
    return out;
  } finally {
    fs.closeSync(fd);
  }
}

export function readPrivateFile(filePath: string, maxBytes: number, heldLock?: ProfileLock): Buffer | null {
  const directory = path.dirname(filePath);
  if (!heldLock) assertSecureProfileDir(directory);
  const handle = directoryHandleFor(directory, heldLock);
  try {
    return readPrivateFileAt(handle.fd, path.basename(filePath), maxBytes);
  } finally {
    if (handle.owned) fs.closeSync(handle.fd);
  }
}

export function readSession(
  dir: string = profileDir(),
  heldLock?: ProfileLock,
): Session | null {
  if (!heldLock) assertSecureProfileDir(dir);
  const p = sessionPath(dir);
  const bytes = readPrivateFile(p, MAX_SESSION_BYTES, heldLock);
  if (!bytes) return null;
  let parsed: Partial<Session>;
  try {
    parsed = JSON.parse(bytes.toString("utf8")) as Partial<Session>;
  } catch {
    throw new Error("profile session is not valid JSON; log in again");
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
  if (!heldLock) assertSecureProfileDir(dir);
  const bytes = readPrivateFile(pendingSessionPath(dir), MAX_SESSION_BYTES, heldLock);
  if (!bytes) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("pending login state is not valid JSON; inspect it before retrying");
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
  const handle = directoryHandleFor(dir, heldLock);
  let entries: string[];
  try {
    entries = fs.readdirSync(path.join(PROFILE_PROC_FD_ROOT, String(handle.fd)));
  } finally {
    if (handle.owned) fs.closeSync(handle.fd);
  }
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
  const size = typeof contents === "string" ? Buffer.byteLength(contents, "utf8") : contents.byteLength;
  if (size > MAX_PRIVATE_FILE_BYTES) {
    throw new Error(`profile file exceeds maximum size of ${MAX_PRIVATE_FILE_BYTES} bytes`);
  }
  const parent = path.dirname(destination);
  if (!heldLock) ensureProfileDir(parent);
  const handle = directoryHandleFor(parent, heldLock);
  const directoryFd = handle.fd;
  const name = path.basename(destination);
  const temporaryName = `.${name}-${process.pid}-${randomUUID()}.tmp`;
  const temporary = anchoredProfilePath(directoryFd, temporaryName);
  const target = anchoredProfilePath(directoryFd, name);
  try {
    try {
      const existing = fs.lstatSync(target);
      if (existing.isSymbolicLink()) throw profileSecurityError(destination, "secret file must not be a symlink");
      if (!existing.isFile()) throw profileSecurityError(destination, "secret file must be a regular file");
      if (existing.uid !== currentUid() || (existing.mode & 0o077) !== 0) {
        throw profileSecurityError(destination, "secret file has unsafe ownership or permissions");
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try {
      fs.writeFileSync(fd, contents);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(temporary, target);
    fs.fsyncSync(directoryFd);
  } finally {
    try {
      fs.rmSync(temporary);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    if (handle.owned) fs.closeSync(directoryFd);
  }
}

export function writeSession(
  session: Session,
  dir: string = profileDir(),
): void {
  const lock = acquireProfileLock(dir);
  try {
    writeSessionUnlocked(session, dir, lock);
  } finally {
    lock.release();
  }
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
  writePrivateFile(sessionPath(dir), serializeBoundedSession(session, "profile session"), heldLock);
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
    serializeBoundedSession(pending, "pending login state"),
    heldLock,
  );
}

export function writeLogoutMarkerUnlocked(dir: string = profileDir(), heldLock?: ProfileLock): void {
  writePrivateFile(logoutMarkerPath(dir), "server-revoked\n", heldLock);
}

export function hasLogoutMarker(dir: string = profileDir(), heldLock?: ProfileLock): boolean {
  const marker = readPrivateFile(logoutMarkerPath(dir), 1024, heldLock);
  if (!marker) return false;
  if (marker.toString("utf8") !== "server-revoked\n") {
    throw new Error("logout cleanup marker is invalid; inspect the profile before retrying");
  }
  return true;
}

/** Clears all local state for this profile (session + crypto store). */
export function clearProfile(dir: string = profileDir()): void {
  const lock = acquireProfileLock(dir);
  try {
    clearProfileUnlocked(dir, {}, lock);
  } finally {
    lock.release();
  }
}

export function clearProfileUnlocked(
  dir: string = profileDir(),
  options: { preserveLogoutMarker?: boolean } = {},
  heldLock?: ProfileLock,
): void {
  const sp = sessionPath(dir);
  const pp = pendingSessionPath(dir);
  const cp = cryptoSnapshotPath(dir);
  const marker = logoutMarkerPath(dir);
  if (!heldLock) {
    assertSecureProfileDir(dir);
    assertSecureProfileFile(sp);
    assertSecureProfileFile(pp);
    assertSecureProfileFile(cp);
    assertSecureProfileFile(marker);
  }
  const preserveLogoutMarker = options.preserveLogoutMarker === true;
  const handle = directoryHandleFor(dir, heldLock);
  const directoryFd = handle.fd;
  const filesToRemove = preserveLogoutMarker
    ? [path.basename(sp), path.basename(pp), path.basename(cp)]
    : [path.basename(sp), path.basename(pp), path.basename(cp), path.basename(marker)];
  try {
    // Validate every known state entry before removing any of them. If a
    // known path became unsafe, retain all credentials for an explicit retry.
    // Unexpected extra state is checked after known entries are removed so a
    // revoke marker can make remote logout idempotent while it is inspected.
    for (const file of filesToRemove) {
      try {
        const anchored = anchoredProfilePath(directoryFd, file);
        const stat = fs.lstatSync(anchored);
        const target = path.join(dir, file);
        if (stat.isSymbolicLink()) throw profileSecurityError(target, "secret file must not be a symlink");
        if (!stat.isFile()) throw profileSecurityError(target, "secret file must be a regular file");
        if (stat.uid !== currentUid()) throw profileSecurityError(target, "secret file has a different owner");
        if ((stat.mode & 0o077) !== 0) {
          throw profileSecurityError(target, "secret file is accessible by group or other users");
        }
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    for (const file of filesToRemove) {
      try {
        const anchored = anchoredProfilePath(directoryFd, file);
        const stat = fs.lstatSync(anchored);
        const target = path.join(dir, file);
        if (stat.isSymbolicLink()) throw profileSecurityError(target, "secret file must not be a symlink");
        if (!stat.isFile()) throw profileSecurityError(target, "secret file must be a regular file");
        if (stat.uid !== currentUid()) throw profileSecurityError(target, "secret file has a different owner");
        if ((stat.mode & 0o077) !== 0) {
          throw profileSecurityError(target, "secret file is accessible by group or other users");
        }
        fs.rmSync(anchored);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    const remaining = fs
      .readdirSync(path.join(PROFILE_PROC_FD_ROOT, String(directoryFd)))
      .filter((entry) => entry !== path.basename(profileLockPath(dir)))
      .filter((entry) => !preserveLogoutMarker || entry !== path.basename(marker));
    if (remaining.length > 0) {
      throw new Error("profile cleanup is incomplete; inspect remaining private state before retrying");
    }
    if (preserveLogoutMarker) {
      try {
        fs.rmSync(anchoredProfilePath(directoryFd, path.basename(marker)));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  } finally {
    if (handle.owned) fs.closeSync(directoryFd);
  }
}
