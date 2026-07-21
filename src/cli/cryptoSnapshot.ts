/**
 * Cross-process crypto persistence (THE central challenge — see docs/CLI_SPEC.md).
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
 * is Option 1 from the spec (disk-persistent crypto store) implemented via
 * generic export/import over the *public* IndexedDB API (databases(), cursors,
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
import * as fs from "node:fs";
import * as v8 from "node:v8";

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

function getIndexedDB(): IDBFactory {
  const idb = (globalThis as unknown as { indexedDB?: IDBFactory }).indexedDB;
  if (!idb) {
    throw new Error(
      "cryptoSnapshot: globalThis.indexedDB is not set — import 'fake-indexeddb/auto' before calling exportIndexedDB/importIndexedDB",
    );
  }
  return idb;
}

function promisifyRequest<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function promisifyTxDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error("IndexedDB transaction aborted"));
  });
}

function readAllRecords(store: IDBObjectStore): Promise<StoreRecord[]> {
  return new Promise((resolve, reject) => {
    const out: StoreRecord[] = [];
    const outOfLine = store.keyPath === null;
    const req = store.openCursor();
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      const cursor = req.result;
      if (cursor) {
        out.push(
          outOfLine
            ? { key: cursor.primaryKey, value: cursor.value }
            : { value: cursor.value },
        );
        cursor.continue();
      } else {
        resolve(out);
      }
    };
  });
}

/** Dumps every IndexedDB database currently visible to this process. */
export async function exportIndexedDB(): Promise<CryptoSnapshot> {
  const idb = getIndexedDB();
  const infos = await idb.databases();
  const dbs: DbSnapshot[] = [];

  for (const info of infos) {
    if (!info.name) continue;
    const db = await promisifyRequest(idb.open(info.name, info.version));
    try {
      const storeNames = Array.from(db.objectStoreNames);
      const stores: StoreSpec[] = [];
      const records: Record<string, StoreRecord[]> = {};

      if (storeNames.length > 0) {
        const tx = db.transaction(storeNames, "readonly");
        for (const storeName of storeNames) {
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
          records[storeName] = await readAllRecords(store);
        }
        await promisifyTxDone(tx);
      }

      dbs.push({ name: info.name, version: db.version, stores, records });
    } finally {
      db.close();
    }
  }

  return { dbs };
}

/** Recreates every database/store/index/record from a snapshot into the
 * current (assumed empty) IndexedDB factory. */
export async function importIndexedDB(snapshot: CryptoSnapshot): Promise<void> {
  const idb = getIndexedDB();

  for (const dbSnap of snapshot.dbs) {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = idb.open(dbSnap.name, Math.max(dbSnap.version, 1));
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
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

    try {
      const storeNames = dbSnap.stores.map((s) => s.name);
      if (storeNames.length > 0) {
        const tx = db.transaction(storeNames, "readwrite");
        for (const store of dbSnap.stores) {
          const os = tx.objectStore(store.name);
          for (const rec of dbSnap.records[store.name] ?? []) {
            if (store.keyPath === null) {
              os.put(rec.value, rec.key as IDBValidKey);
            } else {
              os.put(rec.value);
            }
          }
        }
        await promisifyTxDone(tx);
      }
    } finally {
      db.close();
    }
  }
}

export function loadSnapshotFromDisk(path: string): CryptoSnapshot | null {
  if (!fs.existsSync(path)) return null;
  const buf = fs.readFileSync(path);
  if (buf.length === 0) return null;
  return v8.deserialize(buf) as CryptoSnapshot;
}

export function saveSnapshotToDisk(path: string, snapshot: CryptoSnapshot): void {
  fs.writeFileSync(path, v8.serialize(snapshot), { mode: 0o600 });
}

/** Loads the on-disk snapshot (if any) into the current process's fake-indexeddb. */
export async function restoreCryptoStore(path: string): Promise<void> {
  const snapshot = loadSnapshotFromDisk(path);
  if (snapshot) {
    await importIndexedDB(snapshot);
  }
}

/** Dumps the current process's fake-indexeddb to disk for the next process. */
export async function persistCryptoStore(path: string): Promise<void> {
  const snapshot = await exportIndexedDB();
  saveSnapshotToDisk(path, snapshot);
}
