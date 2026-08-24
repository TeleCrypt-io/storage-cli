import "fake-indexeddb/auto";
import { afterEach, describe, expect, it } from "vitest";
import {
  exportIndexedDB,
  importIndexedDB,
  TELECRYPT_CRYPTO_DATABASE_PREFIX,
} from "../src/cryptoSnapshot.js";

const createdNames: string[] = [];

function createDatabase(name: string, stores = ["store"]): Promise<void> {
  createdNames.push(name);
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => {
      for (const store of stores) request.result.createObjectStore(store);
    };
    request.onsuccess = () => {
      request.result.close();
      resolve();
    };
    request.onerror = () => reject(request.error);
  });
}

afterEach(async () => {
  for (const name of createdNames.splice(0)) {
    await new Promise<void>((resolve) => {
      const request = indexedDB.deleteDatabase(name);
      request.onsuccess = request.onerror = request.onblocked = () => resolve();
    });
  }
});

describe("crypto snapshot database scope", () => {
  it("exports only the published TeleCrypt crypto database prefix", async () => {
    await createDatabase(`${TELECRYPT_CRYPTO_DATABASE_PREFIX}user::device`);
    await createDatabase("unrelated-application-database");

    const snapshot = await exportIndexedDB();

    expect(snapshot.dbs.map(({ name }) => name)).toEqual([
      `${TELECRYPT_CRYPTO_DATABASE_PREFIX}user::device`,
    ]);
  });

  it("rejects databases outside the published prefix", async () => {
    await expect(importIndexedDB({
      dbs: [
        {
          name: "unrelated-application-database",
          version: 1,
          stores: [],
          records: {},
        },
      ],
    })).rejects.toThrow(/invalid database/);

    expect((await indexedDB.databases()).some(({ name }) => name === "unrelated-application-database")).toBe(
      false,
    );
  });

  it("rejects duplicate schema names and undeclared record paths before import", async () => {
    const name = `${TELECRYPT_CRYPTO_DATABASE_PREFIX}invalid`;
    await expect(importIndexedDB({
      dbs: [
        { name, version: 1, stores: [], records: {} },
        { name, version: 1, stores: [], records: {} },
      ],
    })).rejects.toThrow(/duplicate databases/);

    await expect(importIndexedDB({
      dbs: [{
        name,
        version: 1,
        stores: [],
        records: { undeclared: [] },
      }],
    })).rejects.toThrow(/undeclared store/);
  });

  it("requires record keys to match the declared IndexedDB key path", async () => {
    const name = `${TELECRYPT_CRYPTO_DATABASE_PREFIX}keys`;
    await expect(importIndexedDB({
      dbs: [{
        name,
        version: 1,
        stores: [{ name: "store", keyPath: null, autoIncrement: false, indexes: [] }],
        records: { store: [{ value: "missing out-of-line key" }] },
      }],
    })).rejects.toThrow(/record key does not match/);
  });

  it("exports every store without reusing an auto-committed transaction", async () => {
    const name = `${TELECRYPT_CRYPTO_DATABASE_PREFIX}multi-store`;
    await createDatabase(name, ["first", "second"]);

    const snapshot = await exportIndexedDB();

    expect(snapshot.dbs.find((db) => db.name === name)?.stores.map(({ name: store }) => store)).toEqual([
      "first",
      "second",
    ]);
  });

  it("fails before touching IndexedDB when snapshot persistence is cancelled", async () => {
    const controller = new AbortController();
    controller.abort(new Error("cancelled by test"));

    await expect(exportIndexedDB(controller.signal)).rejects.toThrow("cancelled by test");
  });
});
