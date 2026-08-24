import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Session } from "../src/profile.js";

const mocks = vi.hoisted(() => ({
  runDeviceCodeLogin: vi.fn(),
  initStorageForNewSession: vi.fn(),
  requestServerLogout: vi.fn(),
}));

vi.mock("../src/oidc.js", async () => {
  const actual = await vi.importActual<typeof import("../src/oidc.js")>("../src/oidc.js");
  return { ...actual, runDeviceCodeLogin: mocks.runDeviceCodeLogin };
});
vi.mock("../src/storage.js", () => ({ initStorageForNewSession: mocks.initStorageForNewSession }));
vi.mock("../src/logout.js", async () => {
  const actual = await vi.importActual<typeof import("../src/logout.js")>("../src/logout.js");
  return { ...actual, requestServerLogout: mocks.requestServerLogout };
});

import { loginAndInitialize } from "../src/loginTransaction.js";
import { OidcLoginError } from "../src/oidc.js";
import { acquireProfileLock, assertFreshProfileUnlocked, cryptoSnapshotPath, logoutMarkerPath, pendingSessionPath, readPendingSession, readSession, sessionPath, writeSessionUnlocked } from "../src/profile.js";

const SESSION: Session = {
  homeserver: "https://backend.telecrypt.io",
  userId: "@alice:telecrypt.io",
  matrixServerName: "telecrypt.io",
  deviceId: "NEWDEVICE",
  accessToken: "new-access-token",
  oidcIssuer: "https://backend.telecrypt.io/",
  refreshToken: "new-refresh-token",
  oidcClientId: "client",
  oidcTokenEndpoint: "https://backend.telecrypt.io/token",
  oidcRevocationEndpoint: "https://backend.telecrypt.io/revoke",
};

const dirs: string[] = [];

afterEach(() => {
  delete process.env.TELECRYPT_IO_STORAGE_HOME;
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  mocks.runDeviceCodeLogin.mockReset();
  mocks.initStorageForNewSession.mockReset();
  mocks.requestServerLogout.mockReset();
});

function profileDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "telecrypt-login-transaction-"));
  fs.chmodSync(dir, 0o700);
  dirs.push(dir);
  process.env.TELECRYPT_IO_STORAGE_HOME = dir;
  return dir;
}

describe("fenced login transaction", () => {
  it.each(["session", "crypto snapshot", "logout marker"])("refuses authorization over %s state", async (state) => {
    const dir = profileDir();
    if (state === "session") fs.writeFileSync(sessionPath(dir), JSON.stringify(SESSION), { mode: 0o600 });
    if (state === "crypto snapshot") fs.writeFileSync(cryptoSnapshotPath(dir), Buffer.from([1]), { mode: 0o600 });
    if (state === "logout marker") fs.writeFileSync(logoutMarkerPath(dir), "server-revoked\n", { mode: 0o600 });

    await expect(loginAndInitialize(SESSION.homeserver, { onVerification: vi.fn() })).rejects.toThrow(/profile is not empty/);
    expect(mocks.runDeviceCodeLogin).not.toHaveBeenCalled();
    expect(() => assertFreshProfileUnlocked(dir)).toThrow(/profile is not empty/);
  });

  it("holds the profile fence across authorization and initialization", async () => {
    profileDir();
    let resolveLogin!: (session: Session) => void;
    mocks.runDeviceCodeLogin.mockReturnValue(new Promise<Session>((resolve) => { resolveLogin = resolve; }));
    mocks.initStorageForNewSession.mockResolvedValue({ close: vi.fn().mockResolvedValue(undefined) });

    const first = loginAndInitialize(SESSION.homeserver, { onVerification: vi.fn() });
    await vi.waitFor(() => expect(mocks.runDeviceCodeLogin).toHaveBeenCalled());
    await expect(loginAndInitialize(SESSION.homeserver, { onVerification: vi.fn() })).rejects.toThrow(/profile is busy/);
    resolveLogin(SESSION);
    await expect(first).resolves.toEqual(SESSION);
  });

  it("revokes the new server session and clears partial state after initialization failure", async () => {
    const dir = profileDir();
    mocks.runDeviceCodeLogin.mockResolvedValue(SESSION);
    mocks.initStorageForNewSession.mockRejectedValue(new Error("crypto initialization failed"));
    mocks.requestServerLogout.mockResolvedValue(undefined);

    await expect(loginAndInitialize(SESSION.homeserver, { onVerification: vi.fn() })).rejects.toThrow(
      "server session was revoked",
    );
    expect(mocks.requestServerLogout).toHaveBeenCalledWith(
      expect.objectContaining(SESSION),
      undefined,
      expect.any(AbortSignal),
      expect.any(Function),
    );
    expect(fs.existsSync(sessionPath(dir))).toBe(false);
    const lock = acquireProfileLock(dir);
    lock.release();
  });

  it("retains the exact new session when revocation cannot be confirmed", async () => {
    const dir = profileDir();
    mocks.runDeviceCodeLogin.mockResolvedValue(SESSION);
    mocks.initStorageForNewSession.mockRejectedValue(new Error("crypto initialization failed"));
    mocks.requestServerLogout.mockRejectedValue(new Error("offline"));

    await expect(loginAndInitialize(SESSION.homeserver, { onVerification: vi.fn() })).rejects.toThrow(
      "server session retained for retry",
    );
    expect(readSession(dir)).toEqual(SESSION);
    const lock = acquireProfileLock(dir);
    lock.release();
  });

  it("revokes the latest persisted credentials after initialization refreshes the session", async () => {
    profileDir();
    const latest = {
      ...SESSION,
      accessToken: "latest-access-token",
      refreshToken: "latest-refresh-token",
    };
    mocks.runDeviceCodeLogin.mockResolvedValue(SESSION);
    mocks.initStorageForNewSession.mockImplementation(async (_session, dir, lock) => {
      writeSessionUnlocked(latest, dir, lock);
      throw new Error("initialization failed after refresh");
    });
    mocks.requestServerLogout.mockResolvedValue(undefined);

    await expect(loginAndInitialize(SESSION.homeserver, { onVerification: vi.fn() })).rejects.toThrow(
      "server session was revoked",
    );
    expect(mocks.requestServerLogout).toHaveBeenCalledWith(
      expect.objectContaining({ accessToken: "latest-access-token", refreshToken: "latest-refresh-token" }),
      undefined,
      expect.any(AbortSignal),
      expect.any(Function),
    );
  });

  it("persists token-bearing pending state when identity verification fails", async () => {
    const dir = profileDir();
    const pending = {
      homeserver: SESSION.homeserver,
        deviceId: SESSION.deviceId,
        accessToken: SESSION.accessToken,
        oidcIssuer: SESSION.oidcIssuer,
        refreshToken: SESSION.refreshToken,
        oidcClientId: SESSION.oidcClientId,
        oidcTokenEndpoint: SESSION.oidcTokenEndpoint,
        oidcRevocationEndpoint: SESSION.oidcRevocationEndpoint,
      matrixServerName: SESSION.matrixServerName,
    };
    mocks.runDeviceCodeLogin.mockRejectedValue(new OidcLoginError("OIDC identity verification failed", pending));
    mocks.requestServerLogout.mockRejectedValue(new Error("offline"));

    await expect(loginAndInitialize(SESSION.homeserver, { onVerification: vi.fn() })).rejects.toThrow(
      "server session retained for retry",
    );
    expect(readPendingSession(dir)).toMatchObject(pending);
    expect(fs.existsSync(pendingSessionPath(dir))).toBe(true);
  });
});
