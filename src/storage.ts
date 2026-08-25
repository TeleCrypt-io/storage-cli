import "fake-indexeddb/auto";
import { CryptoEvent } from "matrix-js-sdk/lib/crypto-api/index.js";
import { TeleCryptIOStorage } from "@telecrypt-io/storage";
import {
  acquireProfileLock,
  cryptoSnapshotPath,
  canonicalMatrixServerName,
  isBoundedOpaqueValue,
  isCanonicalMatrixUserId,
  profileDir,
  type ProfileLock,
  readSession,
  writeSessionUnlocked,
  Session,
} from "./profile.js";
import { persistCryptoStore, restoreCryptoStore } from "./cryptoSnapshot.js";
import { buildTokenRefreshFunction, StorageError } from "@telecrypt-io/storage/core";
import { assertOidcEndpoint, assertTrustedHomeserver } from "./oidc.js";
import { commandSignal, settlePromiseWithin } from "./cancellation.js";

const CRYPTO_SNAPSHOT_TIMEOUT_MS = 30_000;
const STORAGE_OPEN_TIMEOUT_MS = 30_000;
export const STORAGE_OPERATION_TIMEOUT_MS = 120_000;

export interface OpenedStorage {
  storage: TeleCryptIOStorage;
  session: Session;
  /** Runs one SDK operation with a combined cancellation/deadline signal.
   * Cancellation is joined for a bounded grace period before the command may
   * snapshot or unlock; a non-cooperative operation fails closed. */
  run: <T>(
    operation: (signal: AbortSignal) => Promise<T>,
    label: string,
    timeoutMs?: number,
  ) => Promise<T>;
  /** Persists the crypto store back to disk and stops the client. Call this
   * in a `finally` block around every command that opens storage, so the
   * next CLI invocation sees whatever this one learned (new megolm sessions,
   * device keys, etc.) — this is what makes decryption survive across
   * separate processes. */
  close: () => Promise<void>;
}

export function withRefreshedTokens(
  session: Session,
  tokens: { accessToken: string; refreshToken?: string },
): Session {
  if (!isBoundedOpaqueValue(tokens.accessToken) || (tokens.refreshToken !== undefined && !isBoundedOpaqueValue(tokens.refreshToken))) {
    throw new StorageError("OIDC refresh response contained an invalid token");
  }
  return {
    ...session,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken ?? session.refreshToken,
  };
}

interface RefreshState {
  active: boolean;
}

interface BackupObservation {
  remaining?: number;
  onRemaining: (remaining: number) => void;
}

// The SDK event is also emitted during client startup. Keep the latest value
// so a command that starts after the engine already reached zero does not wait
// for an event that will never be repeated.
const backupObservations = new WeakMap<object, BackupObservation>();

export function observeBackupProgress(storage: TeleCryptIOStorage): void {
  if (backupObservations.has(storage)) return;
  const client = storage.getClient();
  const observation: BackupObservation = {
    onRemaining: (remaining) => {
      if (Number.isInteger(remaining) && remaining >= 0) observation.remaining = remaining;
    },
  };
  client.on(CryptoEvent.KeyBackupSessionsRemaining, observation.onRemaining);
  backupObservations.set(storage, observation);
}

function stopObservingBackupProgress(storage: TeleCryptIOStorage): void {
  const observation = backupObservations.get(storage);
  if (!observation) return;
  try {
    storage.getClient().removeListener(CryptoEvent.KeyBackupSessionsRemaining, observation.onRemaining);
  } finally {
    backupObservations.delete(storage);
  }
}

/** Clears startup progress before an operation that can create new crypto
 * sessions. A previously observed zero is not evidence that this operation's
 * work has reached the server backup. */
export function markBackupWorkPending(storage: TeleCryptIOStorage): void {
  const observation = backupObservations.get(storage);
  if (observation) observation.remaining = undefined;
}

/** Persists the last complete crypto snapshot, but never lets a stalled
 * IndexedDB cursor keep a short-lived CLI process alive forever. The write is
 * atomic, so a timeout leaves the previous snapshot intact for retry. */
async function persistCryptoStoreBounded(snapshotPath: string, lock: ProfileLock): Promise<void> {
  await withStorageDeadline(
    (signal) => persistCryptoStore(snapshotPath, signal, lock),
    CRYPTO_SNAPSHOT_TIMEOUT_MS,
    new AbortController().signal,
    "crypto snapshot persistence timed out; retry the command",
  );
}

async function boundedStorageOperation<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  signal: AbortSignal,
  timeoutMessage: string,
  cancelOperation?: () => void | Promise<void>,
  onLateSuccess?: (value: T) => void,
): Promise<T> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new StorageError("storage operation timeout must be positive");
  }
  if (signal.aborted) throw new StorageError("operation cancelled");
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let boundaryError: StorageError | undefined;
  let rejectBoundary!: (error: StorageError) => void;
  const boundary = new Promise<never>((_, reject) => {
    rejectBoundary = reject;
  });
  const stop = (error: StorageError) => {
    if (boundaryError) return;
    boundaryError = error;
    controller.abort(error);
    try {
      const cleanup = cancelOperation?.();
      const cleanupPromise = Promise.resolve(cleanup);
      // Cancellation hooks are allowed to be asynchronous, but a broken SDK
      // must not make the operation boundary wait forever for one. The
      // bounded join also consumes a late rejection from the hook.
      void settlePromiseWithin(cleanupPromise).then(() => rejectBoundary(error));
    } catch {
      rejectBoundary(error);
    }
  };
  const onAbort = () => stop(new StorageError("operation cancelled"));
  signal.addEventListener("abort", onAbort, { once: true });
  const operationPromise = Promise.resolve().then(() => {
    if (controller.signal.aborted || signal.aborted) {
      throw boundaryError ?? new StorageError("operation cancelled");
    }
    return operation(controller.signal);
  });
  operationPromise.catch(() => undefined);
  // A storage factory can ignore the abort signal and resolve after this
  // boundary has already returned. Stop that late client as soon as it
  // appears; waiting only for the bounded join below would leave a result
  // arriving after the join window running in the background.
  operationPromise.then((value) => {
    if (!boundaryError || !onLateSuccess) return;
    try {
      onLateSuccess(value);
    } catch {
      // The operation has already failed closed; late cleanup is best effort.
    }
  }, () => undefined);
  timer = setTimeout(() => stop(new StorageError(timeoutMessage)), timeoutMs);
  try {
    const result = await Promise.race([operationPromise, boundary]);
    if (boundaryError) throw boundaryError;
    return result;
  } catch (error) {
    if (boundaryError) {
      // Give cooperative SDK work a bounded grace period. If it ignores
      // cancellation, fail closed without persisting a potentially
      // inconsistent snapshot; observe its late rejection so it cannot be
      // unhandled after this command returns.
      await settlePromiseWithin(operationPromise);
      throw boundaryError;
    }
    throw error;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    signal.removeEventListener("abort", onAbort);
  }
}

/** Hard outer bound for core operations whose current SDK surface returns a
 * complete value and does not accept per-operation options. The opened
 * client's abort/close path remains responsible for stopping the underlying
 * Matrix work when this boundary wins. */
export function withStorageDeadline<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  signal: AbortSignal,
  timeoutMessage: string,
  cancelOperation?: () => void | Promise<void>,
  onLateSuccess?: (value: T) => void,
): Promise<T> {
  return boundedStorageOperation(operation, timeoutMs, signal, timeoutMessage, cancelOperation, onLateSuccess);
}

/**
 * Builds a TeleCryptIOStorage for the given OIDC/MAS session (persisted by
 * `storage login`, see src/oidc.ts) through `createFromOidc()` with
 * a token refresh function wired to persist
 * refreshed tokens straight back to this profile's session.json, so a later
 * CLI invocation picks up the refreshed access token rather than the
 * (possibly now-expired) one this process started with. Needs no OIDC
 * discovery here — `oidcTokenEndpoint` was already resolved and persisted at
 * login time (see src/oidc.ts).
 */
async function buildStorageForSession(
  session: Session,
  dir: string,
  refreshState: RefreshState,
  lock: ProfileLock,
  signal?: AbortSignal,
): Promise<TeleCryptIOStorage> {
  const matrixServerName = canonicalMatrixServerName(session.userId);
  if (!isCanonicalMatrixUserId(session.userId) || !matrixServerName || matrixServerName !== session.matrixServerName) {
    throw new StorageError("persisted Matrix identity does not match its server binding");
  }
  const trustedHomeserver = assertTrustedHomeserver(session.homeserver);
  // These values are resolved during login and persisted so refresh never
  // performs discovery again. Revalidate every one before constructing the
  // client: a tampered profile must not redirect bearer credentials or OIDC
  // requests to another origin or outside the issuer path.
  const issuer = new URL(assertOidcEndpoint(session.oidcIssuer, trustedHomeserver, "OIDC issuer"));
  const tokenEndpoint = assertOidcEndpoint(
    session.oidcTokenEndpoint,
    trustedHomeserver,
    "OIDC token endpoint",
    issuer,
  );
  const revocationEndpoint = session.oidcRevocationEndpoint === undefined
    ? undefined
    : assertOidcEndpoint(
        session.oidcRevocationEndpoint,
        trustedHomeserver,
        "OIDC revocation endpoint",
        issuer,
      );

  // OAuth providers may rotate a refresh token once and omit it from a later response. Track the
  // latest persisted token set so a later omission cannot resurrect the pre-rotation token that
  // was present when this CLI process started.
  let currentSession = session;
  const persistRefreshedTokens = async (tokens: { accessToken: string; refreshToken?: string }) => {
      if (!refreshState.active) throw new StorageError("storage command is closing; retry the operation");
      currentSession = withRefreshedTokens(currentSession, tokens);
      writeSessionUnlocked(currentSession, dir, lock);
  };
  const tokenRefreshFunction = buildTokenRefreshFunction(
    {
      issuer: issuer.toString(),
      token_endpoint: tokenEndpoint,
      ...(revocationEndpoint === undefined ? {} : { revocation_endpoint: revocationEndpoint }),
    },
    session.oidcClientId,
    persistRefreshedTokens,
    session.deviceId,
  );

  return TeleCryptIOStorage.createFromOidc({
    baseUrl: trustedHomeserver,
    serverName: session.matrixServerName,
    userId: session.userId,
    accessToken: session.accessToken,
    deviceId: session.deviceId,
    refreshToken: session.refreshToken,
    tokenRefreshFunction,
    signal,
  });
}

async function createStorageForSession(
  session: Session,
  dir: string,
  refreshState: RefreshState,
  lock: ProfileLock,
  signal: AbortSignal,
): Promise<TeleCryptIOStorage> {
  return boundedStorageOperation(
    (operationSignal) => buildStorageForSession(
      session,
      dir,
      refreshState,
      lock,
      operationSignal,
    ),
    STORAGE_OPEN_TIMEOUT_MS,
    signal,
    "storage client initialization timed out; retry the command",
    undefined,
    (lateStorage) => {
      try {
        lateStorage.getClient().stopClient();
      } catch {
        // The timeout has already failed closed; retain that result.
      }
    },
  );
}

function createOpenedStorage(
  storage: TeleCryptIOStorage,
  session: Session,
  dir: string,
  lock: ProfileLock,
  ownsLock: boolean,
  refreshState: RefreshState,
  signal: AbortSignal,
): OpenedStorage {
  const snapshotPath = cryptoSnapshotPath(dir);
  observeBackupProgress(storage);
  let closed = false;
  let snapshotSafe = true;
  let activeOperation: Promise<unknown> | undefined;
  const onAbort = () => {
    // Most core operations use the Matrix client directly and therefore do not
    // have a per-operation options object. Stopping the client is the SDK's
    // supported cancellation boundary for those in-flight requests; close()
    // below still persists local crypto state and releases the profile lock.
    try {
      snapshotSafe = false;
      storage.getClient().stopClient();
    } catch {
      // Cleanup below retains the original cancellation result.
    }
  };
  signal.addEventListener("abort", onAbort, { once: true });
  if (signal.aborted) onAbort();

  const run = async <T>(
    operation: (operationSignal: AbortSignal) => Promise<T>,
    label: string,
    timeoutMs = STORAGE_OPERATION_TIMEOUT_MS,
  ): Promise<T> => {
    if (closed) throw new StorageError("storage command is closing; retry the operation");
    if (activeOperation) throw new StorageError("another storage operation is already active");
    const running = withStorageDeadline(
      operation,
      timeoutMs,
      signal,
      `${label} timed out; retry the command`,
      () => {
        snapshotSafe = false;
        storage.getClient().stopClient();
      },
    );
    activeOperation = running;
    try {
      return await running;
    } finally {
      if (activeOperation === running) activeOperation = undefined;
    }
  };

  const close = async () => {
    if (closed) return;
    closed = true;
    refreshState.active = false;
    signal.removeEventListener("abort", onAbort);
    try {
      if (activeOperation) {
        try {
          await activeOperation;
        } catch {
          // The command operation already owns its failure result.
        }
      }
      stopObservingBackupProgress(storage);
      storage.getClient().stopClient();
      if (snapshotSafe) await persistCryptoStoreBounded(snapshotPath, lock);
    } finally {
      try {
        stopObservingBackupProgress(storage);
        storage.getClient().stopClient();
      } finally {
        if (ownsLock) lock.release();
      }
    }
  };

  return { storage, session, run, close };
}

/**
 * Opens a TeleCryptIOStorage bound to the current profile's session, having first
 * restored the crypto store snapshot (if any) from a previous CLI
 * invocation. Throws StorageError("not logged in") if there is no session.
 */
export async function openStorage(
  dir: string = profileDir(),
  signal: AbortSignal = commandSignal,
): Promise<OpenedStorage> {
  const lock = acquireProfileLock(dir);
  if (signal.aborted) {
    lock.release();
    throw new StorageError("operation cancelled");
  }
  let session: Session | null = null;
  try {
    session = readSession(dir, lock);
  } catch (error) {
    lock.release();
    throw error;
  }
  if (!session) {
    lock.release();
    throw new StorageError("not logged in — run `telecrypt-io storage login` first");
  }

  const snapshotPath = cryptoSnapshotPath(dir);
  const refreshState: RefreshState = { active: true };
  let storage!: TeleCryptIOStorage;
  try {
    await boundedStorageOperation(
      (operationSignal) => restoreCryptoStore(snapshotPath, operationSignal, lock),
      STORAGE_OPEN_TIMEOUT_MS,
      signal,
      "crypto snapshot restore timed out; retry the command",
    );

    storage = await createStorageForSession(
      session,
      dir,
      refreshState,
      lock,
      signal,
    );
  } catch (error) {
    refreshState.active = false;
    lock.release();
    throw error;
  }

  return createOpenedStorage(storage, session, dir, lock, true, refreshState, signal);
}

/**
 * If server-side key backup is active for this account, waits (bounded) for
 * the SDK's backup engine to report zero sessions remaining to
 * upload. This matters specifically because a CLI command is a *short-lived
 * process*: the backup engine deliberately fire-and-forgets its upload loop
 * with a randomised 0-10s startup jitter (to avoid a multi-device thundering
 * herd), so a command that creates a new megolm session (recovery setup,
 * or a file upload once recovery is already set up) and then exits
 * immediately can easily outrun that loop, leaving the new key silently
 * absent from the backup — recoverable-looking but not actually recoverable.
 * A timeout is an error: the command must not report success while a key may
 * still be missing from the server-side backup.
 */
export async function waitForBackupSettled(
  storage: TeleCryptIOStorage,
  timeoutMs = 20000,
  signal: AbortSignal = commandSignal,
): Promise<void> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new StorageError("key backup timeout must be positive");
  }
  if (timeoutMs > 120_000) throw new StorageError("key backup timeout exceeds the allowed maximum");
  if (signal.aborted) throw new StorageError("operation cancelled");
  const deadline = Date.now() + timeoutMs;
  const client = storage.getClient();
  const active = await boundedStorageOperation(
    (_operationSignal) => storage.keys.isRecoverySetup(),
    timeoutMs,
    signal,
    "key backup setup status did not become available before timeout; retry the command",
    () => {
      const stoppable = client as unknown as { stopClient?: () => void };
      stoppable.stopClient?.();
    },
  );
  if (signal.aborted) throw new StorageError("operation cancelled");
  if (!active) return;

  const remainingTimeout = deadline - Date.now();
  if (remainingTimeout <= 0) {
    throw new StorageError("key backup did not settle before timeout; retry the command");
  }
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      client.removeListener(CryptoEvent.KeyBackupSessionsRemaining, onRemaining);
      signal.removeEventListener("abort", onAbort);
      if (timer !== undefined) clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    const onRemaining = (remaining: number) => {
      if (remaining === 0) finish();
    };
    const onAbort = () => finish(new StorageError("operation cancelled"));
    if (signal.aborted) {
      onAbort();
      return;
    }
    client.on(CryptoEvent.KeyBackupSessionsRemaining, onRemaining);
    signal.addEventListener("abort", onAbort, { once: true });
    timer = setTimeout(
      () => finish(new StorageError("key backup did not settle before timeout; retry the command")),
      remainingTimeout,
    );
    // The startup observer may have seen the zero event between the recovery
    // status check and this listener registration. Recheck after both
    // listeners are installed so that interleaving cannot turn settled backup
    // into a false timeout.
    if (backupObservations.get(storage)?.remaining === 0) finish();
  });
}

/** Used by login: builds storage for a brand-new session and
 * establishes the initial (empty) crypto store snapshot on disk. */
export async function initStorageForNewSession(
  session: Session,
  dir: string = profileDir(),
  heldLock?: ProfileLock,
  signal: AbortSignal = commandSignal,
): Promise<OpenedStorage> {
  const lock = heldLock ?? acquireProfileLock(dir);
  const ownsLock = !heldLock;
  if (signal.aborted) {
    if (ownsLock) lock.release();
    throw new StorageError("operation cancelled");
  }
  const refreshState: RefreshState = { active: true };

  let storage!: TeleCryptIOStorage;
  try {
    storage = await createStorageForSession(
      session,
      dir,
      refreshState,
      lock,
      signal,
    );
  } catch (error) {
    refreshState.active = false;
    if (ownsLock) lock.release();
    throw error;
  }

  return createOpenedStorage(storage, session, dir, lock, ownsLock, refreshState, signal);
}
