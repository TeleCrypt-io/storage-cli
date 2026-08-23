import { EventEmitter } from "node:events";
import fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { describe, expect, it, vi } from "vitest";
import { CryptoEvent } from "matrix-js-sdk/lib/crypto-api/index.js";
import { initStorageForNewSession, waitForBackupSettled, withRefreshedTokens } from "../src/storage.js";
import type { Session } from "../src/profile.js";

const SESSION: Session = {
  homeserver: "https://backend.example.test",
  userId: "@alice:example.test",
  deviceId: "DEVICE",
  accessToken: "access-original",
  refreshToken: "refresh-original",
  oidcClientId: "client",
  oidcTokenEndpoint: "https://auth.example.test/token",
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

  it("resolves when the backup engine reports zero remaining sessions", async () => {
    const client = new EventEmitter();
    const pending = waitForBackupSettled(storageWithBackup(client), 1000);
    setTimeout(() => client.emit(CryptoEvent.KeyBackupSessionsRemaining, 0), 0);

    await expect(pending).resolves.toBeUndefined();
    expect(client.listenerCount(CryptoEvent.KeyBackupSessionsRemaining)).toBe(0);
  });
});
