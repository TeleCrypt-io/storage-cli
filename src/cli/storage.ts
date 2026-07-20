import "fake-indexeddb/auto";
import { CryptoEvent } from "matrix-js-sdk/lib/crypto-api/index.js";
import { FileBranch, SecureStorage, TreeSpace } from "../SecureStorage.js";
import { cryptoSnapshotPath, ensureProfileDir, profileDir, readSession, Session } from "./profile.js";
import { persistCryptoStore, restoreCryptoStore } from "./cryptoSnapshot.js";
import { CliError } from "./errors.js";
import { waitForCondition } from "./poll.js";

export interface OpenedStorage {
  storage: SecureStorage;
  session: Session;
  /** Persists the crypto store back to disk and stops the client. Call this
   * in a `finally` block around every command that opens storage, so the
   * next CLI invocation sees whatever this one learned (new megolm sessions,
   * device keys, etc.) — this is what makes decryption survive across
   * separate processes. */
  close: () => Promise<void>;
}

/**
 * Opens a SecureStorage bound to the current profile's session, having first
 * restored the crypto store snapshot (if any) from a previous CLI
 * invocation. Throws CliError("not logged in") if there is no session.
 */
export async function openStorage(dir: string = profileDir()): Promise<OpenedStorage> {
  const session = readSession(dir);
  if (!session) {
    throw new CliError("not logged in — run `secure-storage login` first");
  }

  const snapshotPath = cryptoSnapshotPath(dir);
  await restoreCryptoStore(snapshotPath);

  const storage = await SecureStorage.create({
    baseUrl: session.homeserver,
    userId: session.userId,
    accessToken: session.accessToken,
    deviceId: session.deviceId,
  });

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
 * Looks up a folder by ID, polling briefly: a room this same account just
 * created (or was just invited to, by another process) can be momentarily
 * absent from a from-scratch `/sync` before showing up moments later — real
 * async settling, not an instant "not found". Throws a clean CliError if the
 * folder still isn't visible once the poll times out.
 */
export async function requireTree(storage: SecureStorage, folderId: string): Promise<TreeSpace> {
  try {
    return await waitForCondition(() => storage.getTree(folderId), {
      timeoutMs: 15000,
    });
  } catch {
    throw new CliError(`folder not found: ${folderId}`);
  }
}

/** As `requireTree`, but for a specific file within an already-resolved
 * folder — covers the same settling window for a file another process just
 * uploaded. */
export async function requireFile(tree: TreeSpace, fileId: string): Promise<FileBranch> {
  try {
    return await waitForCondition(() => tree.getFile(fileId), { timeoutMs: 15000 });
  } catch {
    throw new CliError(`file not found: ${fileId}`);
  }
}

/**
 * If server-side key backup is active for this account, waits (best-effort,
 * bounded) for the SDK's backup engine to report zero sessions remaining to
 * upload. This matters specifically because a CLI command is a *short-lived
 * process*: the backup engine deliberately fire-and-forgets its upload loop
 * with a randomised 0-10s startup jitter (to avoid a multi-device thundering
 * herd), so a command that creates a new megolm session (recovery setup,
 * or a file upload once recovery is already set up) and then exits
 * immediately can easily outrun that loop, leaving the new key silently
 * absent from the backup — recoverable-looking but not actually recoverable.
 * Never throws: this is a best-effort settle grace period, not a
 * correctness gate on the command's primary result.
 */
export async function waitForBackupSettled(
  storage: SecureStorage,
  timeoutMs = 20000,
): Promise<void> {
  const active = await storage.keys.isRecoverySetup();
  if (!active) return;

  const client = storage.getClient();
  await new Promise<void>((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      client.removeListener(CryptoEvent.KeyBackupSessionsRemaining, onRemaining);
      clearTimeout(timer);
      resolve();
    };
    const onRemaining = (remaining: number) => {
      if (remaining === 0) finish();
    };
    client.on(CryptoEvent.KeyBackupSessionsRemaining, onRemaining);
    const timer = setTimeout(finish, timeoutMs);
  });
}

/** Used by login/register: builds storage for a brand-new session and
 * establishes the initial (empty) crypto store snapshot on disk. */
export async function initStorageForNewSession(
  session: Session,
  dir: string = profileDir(),
): Promise<OpenedStorage> {
  ensureProfileDir(dir);
  const snapshotPath = cryptoSnapshotPath(dir);

  const storage = await SecureStorage.create({
    baseUrl: session.homeserver,
    userId: session.userId,
    accessToken: session.accessToken,
    deviceId: session.deviceId,
  });

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
