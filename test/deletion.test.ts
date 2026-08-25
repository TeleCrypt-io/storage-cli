import { afterEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  deleteFolder: vi.fn(),
  deleteVault: vi.fn(),
  openStorage: vi.fn(),
  close: vi.fn(),
}));

vi.mock("../src/storage.js", () => ({
  markBackupWorkPending: vi.fn(),
  openStorage: mocks.openStorage,
  waitForBackupSettled: vi.fn(),
}));

vi.mock("@telecrypt-io/storage/core", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@telecrypt-io/storage/core")>()),
  deleteFolder: mocks.deleteFolder,
  deleteVault: mocks.deleteVault,
}));

import { main } from "../src/index.js";

describe("CLI authoritative deletion refusals", () => {
  afterEach(() => {
    mocks.deleteFolder.mockReset();
    mocks.deleteVault.mockReset();
    mocks.openStorage.mockReset();
    mocks.close.mockReset();
    vi.restoreAllMocks();
    process.exitCode = undefined;
  });

  it.each([
    ["vault", ["storage", "vault", "delete"], "deleteVault"],
    ["folder", ["storage", "vault", "subfolder", "delete"], "deleteFolder"],
  ] as const)("returns the SDK nonempty %s refusal without reporting deletion", async (_kind, command, operation) => {
    const storage = {};
    const treeId = "!nonempty:example.test";
    mocks.close.mockResolvedValue(undefined);
    mocks.openStorage.mockResolvedValue({
      storage,
      run: vi.fn(async (action: (signal: AbortSignal) => Promise<unknown>) =>
        action(new AbortController().signal)),
      close: mocks.close,
    });
    mocks[operation].mockRejectedValue(
      Object.assign(new Error("cannot delete a nonempty vault or folder; delete its files first"), {
        code: "NON_EMPTY_TREE",
        treeId,
      }),
    );

    let stdout = "";
    let stderr = "";
    vi.spyOn(process.stdout, "write").mockImplementation(((chunk: string | Uint8Array, callback?: () => void) => {
      stdout += String(chunk);
      callback?.();
      return true;
    }) as typeof process.stdout.write);
    vi.spyOn(process.stderr, "write").mockImplementation(((chunk: string | Uint8Array, callback?: () => void) => {
      stderr += String(chunk);
      callback?.();
      return true;
    }) as typeof process.stderr.write);

    await main(["node", "telecrypt-io", ...command, treeId, "--json"]);

    expect(process.exitCode).toBe(1);
    expect(stdout).toBe("");
    expect(JSON.parse(stderr)).toEqual({
      error: "cannot delete a nonempty vault or folder; delete its files first",
    });
    expect(mocks[operation]).toHaveBeenCalledWith(
      storage,
      treeId,
      { signal: expect.any(AbortSignal) },
    );
    expect(mocks.close).toHaveBeenCalledTimes(1);
  });
});
