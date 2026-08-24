import { EventEmitter } from "node:events";
import fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { CryptoEvent } from "matrix-js-sdk/lib/crypto-api/index.js";
import {
  initStorageForNewSession,
  markBackupWorkPending,
  observeBackupProgress,
  waitForBackupSettled,
  withStorageDeadline,
  withRefreshedTokens,
} from "../src/storage.js";
import { acquireProfileLock } from "../src/profile.js";
import type { Session } from "../src/profile.js";

const SESSION: Session = {
  homeserver: "https://backend.telecrypt.io",
  userId: "@alice:telecrypt.io",
  matrixServerName: "telecrypt.io",
  deviceId: "DEVICE",
  accessToken: "access-original",
  oidcIssuer: "https://backend.telecrypt.io/",
  refreshToken: "refresh-original",
  oidcClientId: "client",
  oidcTokenEndpoint: "https://backend.telecrypt.io/token",
  oidcRevocationEndpoint: "https://backend.telecrypt.io/revoke",
};

describe("OIDC session refresh persistence", () => {
  it("keeps the latest rotated refresh token when a later refresh omits one", () => {
    const rotated = withRefreshedTokens(SESSION, {
      accessToken: "access-rotated",
      refreshToken: "refresh-rotated",
    });
    const later = withRefreshedTokens(rotated, { accessToken: "access-later" });

    expect(later).toEqual({
      ...SESSION,
      accessToken: "access-later",
      refreshToken: "refresh-rotated",
    });
  });

  it("rejects malformed rotated bearer tokens before profile persistence", () => {
    expect(() => withRefreshedTokens(SESSION, { accessToken: "bad\naccess" })).toThrow(/invalid token/);
    expect(() => withRefreshedTokens(SESSION, { accessToken: "access-next", refreshToken: "bad refresh" })).toThrow(/invalid token/);
  });

  it("rejects a tampered cross-origin refresh endpoint before opening storage", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-oidc-endpoint-test-"));
    try {
      await expect(
        initStorageForNewSession(
          {
            ...SESSION,
            homeserver: "https://backend.telecrypt.io",
            oidcTokenEndpoint: "https://evil.example/token",
          },
          dir,
        ),
      ).rejects.toThrow(/OIDC token endpoint.*configured OIDC origin/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("releases its owned profile fence when new-session initialization fails", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-init-failure-lock-"));
    try {
      await expect(
        initStorageForNewSession(
          {
            ...SESSION,
            homeserver: "https://backend.telecrypt.io",
            oidcTokenEndpoint: "https://evil.example/token",
          },
          dir,
        ),
      ).rejects.toThrow(/OIDC token endpoint/);
      const lock = acquireProfileLock(dir);
      lock.release();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("server-side key backup settling", () => {
  function storageWithBackup(client: EventEmitter) {
    return {
      keys: { isRecoverySetup: vi.fn().mockResolvedValue(true) },
      getClient: () => client,
    } as never;
  }

  it("fails instead of reporting success when backup does not settle", async () => {
    const client = new EventEmitter();

    await expect(waitForBackupSettled(storageWithBackup(client), 10)).rejects.toThrow(
      "key backup did not settle before timeout; retry the command",
    );
    expect(client.listenerCount(CryptoEvent.KeyBackupSessionsRemaining)).toBe(0);
  });

  it("bounds a hung recovery-status check before attaching a backup listener", async () => {
    const client = new EventEmitter();
    let rejectStatus!: (error: Error) => void;
    const status = new Promise<boolean>((_resolve, reject) => { rejectStatus = reject; });
    Object.assign(client, { stopClient: () => rejectStatus(new Error("client stopped")) });
    const storage = {
      keys: { isRecoverySetup: vi.fn(() => status) },
      getClient: () => client,
    } as never;

    await expect(waitForBackupSettled(storage, 10)).rejects.toThrow(
      "key backup setup status did not become available before timeout; retry the command",
    );
    expect(client.listenerCount(CryptoEvent.KeyBackupSessionsRemaining)).toBe(0);
  });

  it("rejects an invalid backup timeout before waiting", async () => {
    const client = new EventEmitter();
    const isRecoverySetup = vi.fn().mockResolvedValue(true);
    const storage = {
      keys: { isRecoverySetup },
      getClient: () => client,
    } as never;

    await expect(waitForBackupSettled(storage, 0)).rejects.toThrow("key backup timeout must be positive");
    expect(isRecoverySetup).not.toHaveBeenCalled();
  });

  it("aborts and joins a storage operation before returning its deadline", async () => {
    const controller = new AbortController();
    let cancellationJoined = false;
    await expect(
      withStorageDeadline(
        (operationSignal) => new Promise<boolean>((_resolve, reject) => {
          operationSignal.addEventListener("abort", () => {
            setTimeout(() => {
              cancellationJoined = true;
              reject(new Error("stopped"));
            }, 5);
          }, { once: true });
        }),
        10,
        controller.signal,
        "storage operation timed out",
      ),
    ).rejects.toThrow("storage operation timed out");
    expect(cancellationJoined).toBe(true);
  });

  it("does not invoke a scheduled storage operation after cancellation wins the race", async () => {
    const controller = new AbortController();
    const operation = vi.fn().mockResolvedValue(true);
    const pending = withStorageDeadline(
      operation,
      100,
      controller.signal,
      "storage operation timed out",
    );
    controller.abort(new Error("cancelled before storage starts"));

    await expect(pending).rejects.toThrow("operation cancelled");
    expect(operation).not.toHaveBeenCalled();
  });

  it("bounds an asynchronous cancellation hook that never settles", async () => {
    vi.useFakeTimers();
    try {
      const controller = new AbortController();
      const pending = withStorageDeadline(
        () => new Promise<boolean>(() => {}),
        10,
        controller.signal,
        "storage operation timed out",
        () => new Promise<void>(() => {}),
      );
      const failure = expect(pending).rejects.toThrow("storage operation timed out");
      await vi.advanceTimersByTimeAsync(10);
      await vi.advanceTimersByTimeAsync(5_000);
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;
    } finally {
      vi.useRealTimers();
    }
  });

  it("bounds a storage operation that ignores cancellation", async () => {
    vi.useFakeTimers();
    try {
      const controller = new AbortController();
      const pending = withStorageDeadline(
        () => new Promise<boolean>(() => {}),
        10,
        controller.signal,
        "storage operation timed out",
      );
      const failure = expect(pending).rejects.toThrow("storage operation timed out");
      await vi.advanceTimersByTimeAsync(10);
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;
    } finally {
      vi.useRealTimers();
    }
  });

  it("stops a storage client that resolves after the deadline has returned", async () => {
    vi.useFakeTimers();
    try {
      const stopClient = vi.fn();
      const lateStorage = { getClient: () => ({ stopClient }) };
      const pending = withStorageDeadline(
        () => new Promise<typeof lateStorage>((resolve) => {
          setTimeout(() => resolve(lateStorage), 10_000);
        }),
        10,
        new AbortController().signal,
        "storage client initialization timed out",
        undefined,
        (storage) => storage.getClient().stopClient(),
      );
      const failure = expect(pending).rejects.toThrow("storage client initialization timed out");

      await vi.advanceTimersByTimeAsync(10);
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;
      expect(stopClient).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(5_000);
      expect(stopClient).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("resolves when the backup engine reports zero remaining sessions", async () => {
    const client = new EventEmitter();
    const pending = waitForBackupSettled(storageWithBackup(client), 1000);
    setTimeout(() => client.emit(CryptoEvent.KeyBackupSessionsRemaining, 0), 0);

    await expect(pending).resolves.toBeUndefined();
    expect(client.listenerCount(CryptoEvent.KeyBackupSessionsRemaining)).toBe(0);
  });

  it("cancels a pending backup wait and removes its listener", async () => {
    const client = new EventEmitter();
    const controller = new AbortController();
    const pending = waitForBackupSettled(storageWithBackup(client), 1000, controller.signal);
    controller.abort(new Error("cancelled by test"));

    await expect(pending).rejects.toThrow("operation cancelled");
    expect(client.listenerCount(CryptoEvent.KeyBackupSessionsRemaining)).toBe(0);
  });

  it("does not reuse startup zero for work started later", async () => {
    const client = new EventEmitter();
    const storage = storageWithBackup(client);
    observeBackupProgress(storage);
    client.emit(CryptoEvent.KeyBackupSessionsRemaining, 0);
    markBackupWorkPending(storage);

    let settled = false;
    const pending = waitForBackupSettled(storage, 100).then(() => {
      settled = true;
    });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(settled).toBe(false);
    client.emit(CryptoEvent.KeyBackupSessionsRemaining, 0);
    await pending;
    expect(client.listenerCount(CryptoEvent.KeyBackupSessionsRemaining)).toBe(1);
    client.removeAllListeners(CryptoEvent.KeyBackupSessionsRemaining);
  });
});
