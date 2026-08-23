import "fake-indexeddb/auto";
import { CryptoEvent } from "matrix-js-sdk/lib/crypto-api/index.js";
import { TeleCryptIOStorage } from "@telecrypt-io/storage";
import { cryptoSnapshotPath, ensureProfileDir, profileDir, readSession, writeSession, Session } from "./profile.js";
import { persistCryptoStore, restoreCryptoStore } from "./cryptoSnapshot.js";
import { buildTokenRefreshFunction, StorageError } from "@telecrypt-io/storage/core";
import { assertOidcEndpoint } from "./oidc.js";

export interface OpenedStorage {
  storage: TeleCryptIOStorage;
  session: Session;
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
  return {
    ...session,
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken ?? session.refreshToken,
  };
}

/**
 * Builds a TeleCryptIOStorage for the given OIDC/MAS session (persisted by
 * `storage login`, see src/oidc.ts) through `createFromOidc()` with
 * a token refresh function wired to persist
 * refreshed tokens straight back to this profile's session.json, so a later
 * CLI invocation picks up the refreshed access token rather than the
 * (possibly now-expired) one this process started with. Needs no OIDC
 * discovery / `window` shim here — `oidcTokenEndpoint` was already resolved
 * and persisted at login time (see src/oidc.ts).
 */
async function buildStorageForSession(session: Session, dir: string): Promise<TeleCryptIOStorage> {
  // The endpoint is persisted at login time. Validate it again before constructing the client so a
  // tampered profile cannot send refresh credentials to a different origin.
  const tokenEndpoint = assertOidcEndpoint(session.oidcTokenEndpoint, session.homeserver, "OIDC token endpoint");

  // OAuth providers may rotate a refresh token once and omit it from a later response. Track the
  // latest persisted token set so a later omission cannot resurrect the pre-rotation token that
  // was present when this CLI process started.
  let currentSession = session;
  const tokenRefreshFunction = buildTokenRefreshFunction(
    tokenEndpoint,
    session.oidcClientId,
    async (tokens) => {
      currentSession = withRefreshedTokens(currentSession, tokens);
      writeSession(currentSession, dir);
    },
  );

  return TeleCryptIOStorage.createFromOidc({
    baseUrl: session.homeserver,
    userId: session.userId,
    accessToken: session.accessToken,
    deviceId: session.deviceId,
    refreshToken: session.refreshToken,
    tokenRefreshFunction,
  });
}

/**
 * Opens a TeleCryptIOStorage bound to the current profile's session, having first
 * restored the crypto store snapshot (if any) from a previous CLI
 * invocation. Throws StorageError("not logged in") if there is no session.
 */
export async function openStorage(dir: string = profileDir()): Promise<OpenedStorage> {
  const session = readSession(dir);
  if (!session) {
    throw new StorageError("not logged in — run `telecrypt-io storage login` first");
  }

  const snapshotPath = cryptoSnapshotPath(dir);
  await restoreCryptoStore(snapshotPath);

  const storage = await buildStorageForSession(session, dir);

  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    try {
      await persistCryptoStore(snapshotPath);
    } finally {
      storage.getClient().stopClient();
    }
  };

  return { storage, session, close };
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
): Promise<void> {
  const active = await storage.keys.isRecoverySetup();
  if (!active) return;

  const client = storage.getClient();
  await new Promise<void>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      client.removeListener(CryptoEvent.KeyBackupSessionsRemaining, onRemaining);
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    const onRemaining = (remaining: number) => {
      if (remaining === 0) finish();
    };
    client.on(CryptoEvent.KeyBackupSessionsRemaining, onRemaining);
    const timer = setTimeout(
      () => finish(new StorageError("key backup did not settle before timeout; retry the command")),
      timeoutMs,
    );
  });
}

/** Used by login: builds storage for a brand-new session and
 * establishes the initial (empty) crypto store snapshot on disk. */
export async function initStorageForNewSession(
  session: Session,
  dir: string = profileDir(),
): Promise<OpenedStorage> {
  ensureProfileDir(dir);
  const snapshotPath = cryptoSnapshotPath(dir);

  const storage = await buildStorageForSession(session, dir);

  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    try {
      await persistCryptoStore(snapshotPath);
    } finally {
      storage.getClient().stopClient();
    }
  };

  return { storage, session, close };
}
