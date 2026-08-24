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
  MAX_PRIVATE_FILE_BYTES,
  readPrivateFile,
  writePrivateFile,
  type ProfileLock,
} from "./profile.js";

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
export const MAX_SNAPSHOT_BYTES = MAX_PRIVATE_FILE_BYTES;
const MAX_SNAPSHOT_DATABASES = 16;
const MAX_SNAPSHOT_STORES = 128;
const MAX_SNAPSHOT_RECORDS = 100_000;
const MAX_SNAPSHOT_ACCUMULATED_BYTES = MAX_SNAPSHOT_BYTES;
const MAX_SNAPSHOT_NAME_BYTES = 1024;

interface SnapshotBudget {
  records: number;
  bytes: number;
}

function accountSnapshotRecord(budget: SnapshotBudget, record: StoreRecord): void {
  if (budget.records >= MAX_SNAPSHOT_RECORDS) {
    throw new Error("crypto snapshot contains too many records");
  }
  let encoded: Uint8Array;
  try {
    encoded = v8.serialize(record);
  } catch {
    throw new Error("crypto snapshot contains an unserializable record");
  }
  // Include a conservative container overhead. The aggregate budget is
  // checked while cursors are read, before an attacker can accumulate an
  // unbounded in-memory export that is only rejected at final serialization.
  const accounted = encoded.byteLength + 64;
  if (accounted > MAX_SNAPSHOT_ACCUMULATED_BYTES - budget.bytes) {
    throw new Error("crypto snapshot exceeds the 64 MiB aggregate limit");
  }
  budget.bytes += accounted;
  budget.records += 1;
}

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
  budget: SnapshotBudget,
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
      try {
        tx.abort();
      } catch {
        // Preserve the cancellation result if the transaction is already done.
      }
      finish(snapshotAbortError(signal));
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
        try {
          accountSnapshotRecord(budget, record);
        } catch (error) {
          finish(error instanceof Error ? error : new Error(String(error)));
          try {
            tx.abort();
          } catch {
            // The transaction may already have closed after the cursor error.
          }
          return;
        }
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
  const budget: SnapshotBudget = { records: 0, bytes: 0 };

  for (const info of infos) {
    throwIfSnapshotAborted(signal);
    if (!info.name || !info.name.startsWith(TELECRYPT_CRYPTO_DATABASE_PREFIX)) continue;
    if (Buffer.byteLength(info.name, "utf8") > MAX_SNAPSHOT_NAME_BYTES) {
      throw new Error("crypto snapshot database name exceeds the bounded length");
    }
    if (dbs.length >= MAX_SNAPSHOT_DATABASES) throw new Error("crypto snapshot contains too many databases");
    const db = await openDatabase(idb, info.name, info.version, signal);
    try {
      const storeNames = Array.from(db.objectStoreNames);
      const stores: StoreSpec[] = [];
      const records: Record<string, StoreRecord[]> = {};

      if (storeNames.length > 0) {
        if (storeNames.length > MAX_SNAPSHOT_STORES) throw new Error("crypto snapshot contains too many stores");
        for (const storeName of storeNames) {
          throwIfSnapshotAborted(signal);
          if (Buffer.byteLength(storeName, "utf8") > MAX_SNAPSHOT_NAME_BYTES) {
            throw new Error("crypto snapshot store name exceeds the bounded length");
          }
          // Keep each cursor in its own transaction. A readonly IndexedDB
          // transaction may auto-commit as soon as its last request settles;
          // awaiting one store before opening the next would otherwise make
          // the following objectStore lookup race a closed transaction.
          const tx = db.transaction([storeName], "readonly");
          const store = tx.objectStore(storeName);
          const indexes: IndexSpec[] = Array.from(store.indexNames).map((iname) => {
            if (Buffer.byteLength(iname, "utf8") > MAX_SNAPSHOT_NAME_BYTES) {
              throw new Error("crypto snapshot index name exceeds the bounded length");
            }
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
          records[storeName] = await readAllRecords(store, tx, budget, signal);
        }
      }

      dbs.push({ name: info.name, version: db.version, stores, records });
    } finally {
      db.close();
    }
  }

  return { dbs };
}

/** Recreates each published TeleCrypt crypto database/store/index/record from
 * a snapshot into the current (assumed empty) IndexedDB factory. */
export async function importIndexedDB(snapshot: CryptoSnapshot, signal?: AbortSignal): Promise<void> {
  const idb = getIndexedDB();

  throwIfSnapshotAborted(signal);
  validateSnapshot(snapshot);

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
    } finally {
      db.close();
    }
  }
}

export function loadSnapshotFromDisk(path: string, heldLock?: ProfileLock): CryptoSnapshot | null {
  const buf = readPrivateFile(path, MAX_SNAPSHOT_BYTES, heldLock);
  if (!buf) return null;
  if (buf.length === 0) return null;
  let snapshot: unknown;
  try {
    snapshot = v8.deserialize(buf);
  } catch {
    throw new Error("crypto snapshot is unreadable; remove it and retry");
  }
  validateSnapshot(snapshot);
  return snapshot;
}

export function saveSnapshotToDisk(path: string, snapshot: CryptoSnapshot, heldLock?: ProfileLock): void {
  validateSnapshot(snapshot);
  const serialized = v8.serialize(snapshot);
  if (serialized.byteLength > MAX_SNAPSHOT_BYTES) {
    throw new Error("crypto snapshot exceeds the 64 MiB serialized limit");
  }
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

function validateSnapshot(value: unknown): asserts value is CryptoSnapshot {
  if (!value || typeof value !== "object" || !Array.isArray((value as { dbs?: unknown }).dbs)) {
    throw new Error("crypto snapshot has an invalid shape");
  }
  const dbs = (value as CryptoSnapshot).dbs;
  if (dbs.length > MAX_SNAPSHOT_DATABASES) throw new Error("crypto snapshot contains too many databases");
  let totalRecords = 0;
  let accountedBytes = 0;
  const databaseNames = new Set<string>();
  const validName = (name: unknown, kind: string): name is string => {
    if (
      typeof name !== "string" ||
      name.length === 0 ||
      Buffer.byteLength(name, "utf8") > MAX_SNAPSHOT_NAME_BYTES ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(name)
    ) {
      throw new Error(`crypto snapshot ${kind} name is invalid`);
    }
    return true;
  };
  const validKeyPath = (keyPath: unknown): keyPath is string | string[] | null => {
    if (keyPath === null) return true;
    const parts = typeof keyPath === "string" ? [keyPath] : keyPath;
    if (!Array.isArray(parts) || parts.length === 0 || parts.length > 64) return false;
    return parts.every(
      (part) =>
        typeof part === "string" &&
        part.length > 0 &&
        Buffer.byteLength(part, "utf8") <= MAX_SNAPSHOT_NAME_BYTES &&
        !/[\u0000-\u001f\u007f-\u009f]/u.test(part),
    );
  };
  for (const db of dbs) {
    if (!db || !validName(db.name, "database") || !db.name.startsWith(TELECRYPT_CRYPTO_DATABASE_PREFIX)) {
      throw new Error("crypto snapshot contains an invalid database");
    }
    if (databaseNames.has(db.name)) throw new Error("crypto snapshot contains duplicate databases");
    databaseNames.add(db.name);
    if (!Number.isSafeInteger(db.version) || db.version < 1 || !Array.isArray(db.stores) || db.stores.length > MAX_SNAPSHOT_STORES) {
      throw new Error("crypto snapshot contains invalid database metadata");
    }
    if (!db.records || typeof db.records !== "object" || Array.isArray(db.records)) {
      throw new Error("crypto snapshot contains invalid records");
    }
    const storeNames = new Set<string>();
    for (const store of db.stores) {
      if (
        !store ||
        !validName(store.name, "store") ||
        storeNames.has(store.name) ||
        !validKeyPath(store.keyPath) ||
        typeof store.autoIncrement !== "boolean" ||
        !Array.isArray(store.indexes) ||
        !Object.prototype.hasOwnProperty.call(db.records, store.name) ||
        !Array.isArray(db.records[store.name])
      ) {
        throw new Error("crypto snapshot contains invalid store metadata");
      }
      storeNames.add(store.name);
      const indexNames = new Set<string>();
      for (const index of store.indexes) {
        if (
          !index ||
          !validName(index.name, "index") ||
          indexNames.has(index.name) ||
          !validKeyPath(index.keyPath) ||
          index.keyPath === null ||
          typeof index.unique !== "boolean" ||
          typeof index.multiEntry !== "boolean"
        ) {
          throw new Error("crypto snapshot index metadata is invalid");
        }
        indexNames.add(index.name);
      }
      for (const record of db.records[store.name]) {
        if (!record || typeof record !== "object" || !Object.prototype.hasOwnProperty.call(record, "value")) {
          throw new Error("crypto snapshot contains an invalid record");
        }
        const hasKey = Object.prototype.hasOwnProperty.call(record, "key");
        if ((store.keyPath === null) !== hasKey) {
          throw new Error("crypto snapshot record key does not match its store key path");
        }
        const encoded = v8.serialize(record);
        if (encoded.byteLength + 64 > MAX_SNAPSHOT_ACCUMULATED_BYTES - accountedBytes) {
          throw new Error("crypto snapshot exceeds the 64 MiB aggregate limit");
        }
        accountedBytes += encoded.byteLength + 64;
        totalRecords += 1;
        if (totalRecords > MAX_SNAPSHOT_RECORDS) throw new Error("crypto snapshot contains too many records");
      }
    }
    for (const recordName of Object.keys(db.records)) {
      if (!storeNames.has(recordName)) {
        throw new Error("crypto snapshot contains records for an undeclared store");
      }
    }
  }
}
