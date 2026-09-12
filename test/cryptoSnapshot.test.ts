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

  it("ignores databases outside the published prefix when importing", async () => {
    await importIndexedDB({
      dbs: [{ name: "unrelated-application-database", version: 1, stores: [], records: {} }],
    });

    expect((await indexedDB.databases()).some(({ name }) => name === "unrelated-application-database")).toBe(
      false,
    );
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
