/**
 * Cross-process crypto persistence for the process-per-command CLI.
 *
 * A CLI runs each command as a separate OS process. `TeleCryptIOStorage.create()`
 * initialises rust-crypto with `useIndexedDB: true`, but in Node the only
 * IndexedDB available is `fake-indexeddb`, which is a pure in-memory
 * implementation — it evaporates when the process exits. Left alone, every
 * CLI invocation would start with an empty crypto store and be unable to
 * decrypt anything a previous invocation wrote (including its own device's
 * megolm sessions), which also breaks cross-user sharing: userB's upload
 * process sends userA an olm-encrypted room key addressed to userA's device
 * identity; if that identity is regenerated every run, the key is
 * undecryptable and userA can never read userB's file no matter what backup
 * scheme is layered on top.
 *
 * Fix: snapshot fake-indexeddb's databases to disk after each command and
 * reload them before the next one runs, keyed to the profile directory. This
 * provides a disk-persistent crypto store via generic export/import over the
 * *public* IndexedDB API (databases(), cursors,
 * transactions) rather than poking fake-indexeddb's internals — so it isn't
 * coupled to fake-indexeddb's private representation and would keep working
 * against any spec-compliant IndexedDB implementation. Runtime crypto
 * behaviour is otherwise unchanged from what the library's own tests already
 * exercise (keys.test.ts, tree.test.ts 4.6 both run rust-crypto on
 * fake-indexeddb).
 *
 * Binary values (megolm session keys etc.) don't survive JSON, so the
 * snapshot is serialised with Node's structured-clone-capable `node:v8`
 * (de)serialize rather than JSON.
 */
import * as v8 from "node:v8";
import {
  readPrivateFile,
  writePrivateFile,
  type ProfileLock,
} from "./profile.js";
import { attemptCleanup, throwCombinedFailures, withCause } from "./failure.js";

interface IndexSpec {
  name: string;
  keyPath: string | string[];
  unique: boolean;
  multiEntry: boolean;
}

interface StoreSpec {
  name: string;
  keyPath: string | string[] | null;
  autoIncrement: boolean;
  indexes: IndexSpec[];
}

interface StoreRecord {
  key?: unknown; // present only for out-of-line keys (store.keyPath === null)
  value: unknown;
}

interface DbSnapshot {
  name: string;
  version: number;
  stores: StoreSpec[];
  records: Record<string, StoreRecord[]>;
}

export interface CryptoSnapshot {
  dbs: DbSnapshot[];
}

/** Prefix used by @telecrypt-io/storage for its rust-crypto databases. */
export const TELECRYPT_CRYPTO_DATABASE_PREFIX = "telecrypt-io-storage::";

function getIndexedDB(): IDBFactory {
  const idb = (globalThis as unknown as { indexedDB?: IDBFactory }).indexedDB;
  if (!idb) {
    throw new Error(
      "cryptoSnapshot: globalThis.indexedDB is not set — import 'fake-indexeddb/auto' before calling exportIndexedDB/importIndexedDB",
    );
  }
  return idb;
}

function snapshotAbortError(signal?: AbortSignal): Error {
  return signal?.reason instanceof Error ? signal.reason : new Error("crypto snapshot operation cancelled");
}

function throwIfSnapshotAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw snapshotAbortError(signal);
}

function abortableSnapshotOperation<T>(operation: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return operation;
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error, value?: T) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      if (error) reject(error);
      else resolve(value as T);
    };
    const onAbort = () => finish(snapshotAbortError(signal));
    operation.then(
      (value) => finish(undefined, value),
      (error) => finish(error instanceof Error ? error : new Error(String(error))),
    );
    if (signal.aborted) onAbort();
    else signal.addEventListener("abort", onAbort, { once: true });
  });
}

function openDatabase(
  idb: IDBFactory,
  name: string,
  version: number | undefined,
  signal?: AbortSignal,
): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const req = idb.open(name, version);
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", onAbort);
      if (error) reject(error);
      else resolve(req.result);
    };
    const onAbort = () => finish(snapshotAbortError(signal));
    req.onsuccess = () => {
      if (settled) {
        req.result.close();
        return;
      }
      finish();
    };
    req.onerror = () => finish(req.error ?? new Error("IndexedDB open failed"));
    if (signal) {
      if (signal.aborted) onAbort();
      else signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

function promisifyTxDone(tx: IDBTransaction, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", onAbort);
      if (error) reject(error);
      else resolve();
    };
    const onAbort = () => {
      try {
        tx.abort();
      } catch {
        // A transaction that already committed or aborted needs no further
        // cancellation; the bounded error below remains authoritative.
      }
      finish(snapshotAbortError(signal));
    };
    tx.oncomplete = () => finish();
    tx.onerror = () => finish(tx.error ?? new Error("IndexedDB transaction failed"));
    tx.onabort = () => finish(tx.error ?? new Error("IndexedDB transaction aborted"));
    if (signal) {
      if (signal.aborted) onAbort();
      else signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

function readAllRecords(
  store: IDBObjectStore,
  tx: IDBTransaction,
  signal?: AbortSignal,
): Promise<StoreRecord[]> {
  return new Promise((resolve, reject) => {
    const out: StoreRecord[] = [];
    const outOfLine = store.keyPath === null;
    let settled = false;
    const finish = (error?: Error) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", onAbort);
      if (error) reject(error);
      else resolve(out);
    };
    const onAbort = () => {
      const cancellationError = snapshotAbortError(signal);
      try {
        tx.abort();
      } catch (cleanupError) {
        finish(new AggregateError(
          [cancellationError, cleanupError],
          "crypto snapshot read cancellation failed",
          { cause: cancellationError },
        ));
        return;
      }
      finish(cancellationError);
    };
    const req = store.openCursor();
    req.onerror = () => finish(req.error ?? new Error("IndexedDB cursor failed"));
    req.onsuccess = () => {
      if (settled) return;
      const cursor = req.result;
      if (cursor) {
        const record = outOfLine
          ? { key: cursor.primaryKey, value: cursor.value }
          : { value: cursor.value };
        out.push(record);
        cursor.continue();
      } else {
        finish();
      }
    };
    if (signal) {
      if (signal.aborted) onAbort();
      else signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

/** Dumps TeleCrypt crypto databases currently visible to this process. */
export async function exportIndexedDB(signal?: AbortSignal): Promise<CryptoSnapshot> {
  const idb = getIndexedDB();
  throwIfSnapshotAborted(signal);
  const infos = await abortableSnapshotOperation(idb.databases(), signal);
  throwIfSnapshotAborted(signal);
  const dbs: DbSnapshot[] = [];

  for (const info of infos) {
    throwIfSnapshotAborted(signal);
    if (!info.name || !info.name.startsWith(TELECRYPT_CRYPTO_DATABASE_PREFIX)) continue;
    const db = await openDatabase(idb, info.name, info.version, signal);
    let primaryError: unknown;
    let hasPrimary = false;
    try {
      const storeNames = Array.from(db.objectStoreNames);
      const stores: StoreSpec[] = [];
      const records: Record<string, StoreRecord[]> = {};

      if (storeNames.length > 0) {
        for (const storeName of storeNames) {
          throwIfSnapshotAborted(signal);
          // Keep each cursor in its own transaction. A readonly IndexedDB
          // transaction may auto-commit as soon as its last request settles;
          // awaiting one store before opening the next would otherwise make
          // the following objectStore lookup race a closed transaction.
          const tx = db.transaction([storeName], "readonly");
          const store = tx.objectStore(storeName);
          const indexes: IndexSpec[] = Array.from(store.indexNames).map((iname) => {
            const idx = store.index(iname);
            return {
              name: idx.name,
              keyPath: idx.keyPath as string | string[],
              unique: idx.unique,
              multiEntry: idx.multiEntry,
            };
          });
          stores.push({
            name: storeName,
            keyPath: store.keyPath as string | string[] | null,
            autoIncrement: store.autoIncrement,
            indexes,
          });
          records[storeName] = await readAllRecords(store, tx, signal);
        }
      }

      dbs.push({ name: info.name, version: db.version, stores, records });
    } catch (error) {
      hasPrimary = true;
      primaryError = error;
    }
    const cleanupFailures: unknown[] = [];
    attemptCleanup(cleanupFailures, () => db.close());
    if (hasPrimary || cleanupFailures.length > 0) {
      throwCombinedFailures(primaryError, hasPrimary, cleanupFailures, "crypto snapshot database cleanup failed");
    }
  }

  return { dbs };
}

/** Recreates each published TeleCrypt crypto database/store/index/record from
 * a snapshot into the current (assumed empty) IndexedDB factory. */
export async function importIndexedDB(snapshot: CryptoSnapshot, signal?: AbortSignal): Promise<void> {
  const idb = getIndexedDB();

  throwIfSnapshotAborted(signal);

  for (const dbSnap of snapshot.dbs) {
    throwIfSnapshotAborted(signal);
    if (!dbSnap.name.startsWith(TELECRYPT_CRYPTO_DATABASE_PREFIX)) continue;
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      let settled = false;
      const req = idb.open(dbSnap.name, Math.max(dbSnap.version, 1));
      const finish = (error?: Error) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener("abort", onAbort);
        if (error) reject(error);
        else resolve(req.result);
      };
      const onAbort = () => finish(snapshotAbortError(signal));
      req.onupgradeneeded = () => {
        const database = req.result;
        for (const store of dbSnap.stores) {
          const os = database.createObjectStore(store.name, {
            keyPath: store.keyPath ?? undefined,
            autoIncrement: store.autoIncrement,
          });
          for (const idx of store.indexes) {
            os.createIndex(idx.name, idx.keyPath, {
              unique: idx.unique,
              multiEntry: idx.multiEntry,
            });
          }
        }
      };
      req.onsuccess = () => {
        if (settled) {
          req.result.close();
          return;
        }
        finish();
      };
      req.onerror = () => finish(req.error ?? new Error("IndexedDB restore open failed"));
      if (signal) {
        if (signal.aborted) onAbort();
        else signal.addEventListener("abort", onAbort, { once: true });
      }
    });

    let primaryError: unknown;
    let hasPrimary = false;
    try {
      const storeNames = dbSnap.stores.map((s) => s.name);
      if (storeNames.length > 0) {
        throwIfSnapshotAborted(signal);
        const tx = db.transaction(storeNames, "readwrite");
        for (const store of dbSnap.stores) {
          throwIfSnapshotAborted(signal);
          const os = tx.objectStore(store.name);
          for (const rec of dbSnap.records[store.name] ?? []) {
            throwIfSnapshotAborted(signal);
            if (store.keyPath === null) {
              os.put(rec.value, rec.key as IDBValidKey);
            } else {
              os.put(rec.value);
            }
          }
        }
        await promisifyTxDone(tx, signal);
      }
    } catch (error) {
      hasPrimary = true;
      primaryError = error;
    }
    const cleanupFailures: unknown[] = [];
    attemptCleanup(cleanupFailures, () => db.close());
    if (hasPrimary || cleanupFailures.length > 0) {
      throwCombinedFailures(primaryError, hasPrimary, cleanupFailures, "crypto snapshot database cleanup failed");
    }
  }
}

export function loadSnapshotFromDisk(path: string, heldLock?: ProfileLock): CryptoSnapshot | null {
  const buf = readPrivateFile(path, heldLock);
  if (!buf) return null;
  if (buf.length === 0) return null;
  let snapshot: CryptoSnapshot;
  try {
    snapshot = v8.deserialize(buf) as CryptoSnapshot;
  } catch (error) {
    throw withCause(new Error("crypto snapshot is unreadable; remove it and retry"), error);
  }
  return snapshot;
}

export function saveSnapshotToDisk(path: string, snapshot: CryptoSnapshot, heldLock?: ProfileLock): void {
  const serialized = v8.serialize(snapshot);
  writePrivateFile(path, serialized, heldLock);
}

/** Loads the on-disk snapshot (if any) into the current process's fake-indexeddb. */
export async function restoreCryptoStore(
  path: string,
  signal?: AbortSignal,
  heldLock?: ProfileLock,
): Promise<void> {
  throwIfSnapshotAborted(signal);
  const snapshot = loadSnapshotFromDisk(path, heldLock);
  if (snapshot) {
    await importIndexedDB(snapshot, signal);
  }
}

/** Dumps the current process's fake-indexeddb to disk for the next process. */
export async function persistCryptoStore(
  path: string,
  signal?: AbortSignal,
  heldLock?: ProfileLock,
): Promise<void> {
  const snapshot = await exportIndexedDB(signal);
  throwIfSnapshotAborted(signal);
  saveSnapshotToDisk(path, snapshot, heldLock);
}
