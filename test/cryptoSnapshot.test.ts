import "fake-indexeddb/auto";
import { afterEach, describe, expect, it } from "vitest";
import {
  exportIndexedDB,
  importIndexedDB,
  TELECRYPT_CRYPTO_DATABASE_PREFIX,
} from "../src/cryptoSnapshot.js";

const createdNames: string[] = [];

function createDatabase(name: string): Promise<void> {
  createdNames.push(name);
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => request.result.createObjectStore("store");
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

  it("does not import databases outside the published prefix", async () => {
    await importIndexedDB({
      dbs: [
        {
          name: "unrelated-application-database",
          version: 1,
          stores: [],
          records: {},
        },
      ],
    });

    expect((await indexedDB.databases()).some(({ name }) => name === "unrelated-application-database")).toBe(
      false,
    );
  });
});
