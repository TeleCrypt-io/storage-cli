import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { Session } from "../src/profile.js";
import { requestServerLogout, logoutProfile } from "../src/logout.js";
import { cryptoSnapshotPath, logoutMarkerPath, pendingSessionPath, sessionPath, writePendingSessionUnlocked, writeSession } from "../src/profile.js";

const session: Session = {
  homeserver: "https://backend.telecrypt.io",
  userId: "@alice:telecrypt.io",
  matrixServerName: "telecrypt.io",
  deviceId: "DEVICE",
  accessToken: "secret-access-token",
  oidcIssuer: "https://backend.telecrypt.io/auth/",
  refreshToken: "secret-refresh-token",
  oidcClientId: "client-id",
  oidcTokenEndpoint: "https://backend.telecrypt.io/auth/token",
};

const LOGOUT_URL = "https://backend.telecrypt.io/_matrix/client/v3/logout";
const TOKEN_URL = "https://backend.telecrypt.io/auth/token";
const REVOCATION_URL = "https://backend.telecrypt.io/auth/revoke";
const directories: string[] = [];

function fixtureDirectory(prefix: string): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `${prefix}-`));
  directories.push(directory);
  return directory;
}

function exactResponse(url: string, body: BodyInit | null, init: ResponseInit): Response {
  const response = new Response(body, init);
  Object.defineProperty(response, "url", { configurable: true, value: url });
  return response;
}

afterEach(({ task }) => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  const pending = directories.splice(0);
  if (task.result?.state === "fail") {
    process.stderr.write(
      [
        "CLI logout unit test failed; retaining fixture directories for investigation:",
        ...pending,
      ].join("\n") + "\n",
    );
    return;
  }
  for (const directory of pending) fs.rmSync(directory, { recursive: true, force: true });
});

describe("server logout", () => {
  it("rejects a non-loopback HTTP homeserver before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(requestServerLogout({ ...session, homeserver: "http://backend.telecrypt.io" })).rejects.toThrow(
      "must use HTTPS except for the exact loopback host",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects an invalid timeout before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(requestServerLogout(session, 0)).rejects.toThrow("server logout timeout must be positive");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a persisted OIDC revocation endpoint outside the issuer binding", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(requestServerLogout({
      ...session,
      oidcRevocationEndpoint: "https://evil.example/revoke",
    })).rejects.toThrow(/OIDC revocation endpoint/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("revokes a current OAuth session through its bound revocation endpoint", async () => {
    const fetchMock = vi.fn().mockResolvedValue(exactResponse(REVOCATION_URL, null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await requestServerLogout({ ...session, oidcRevocationEndpoint: REVOCATION_URL });

    expect(fetchMock).toHaveBeenCalledWith(
      REVOCATION_URL,
      expect.objectContaining({
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          token: session.accessToken,
          token_type_hint: "access_token",
          client_id: session.oidcClientId,
        }),
        redirect: "manual",
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("rejects incomplete OAuth revocation state before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(requestServerLogout({
      ...session,
      oidcClientId: undefined,
      oidcRevocationEndpoint: REVOCATION_URL,
    })).rejects.toThrow("persisted OIDC revocation state is incomplete");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("retains an OAuth revocation failure response", async () => {
    const fetchMock = vi.fn().mockResolvedValue(exactResponse(
      REVOCATION_URL,
      JSON.stringify({ error: "temporarily unavailable" }),
      { status: 503 },
    ));
    vi.stubGlobal("fetch", fetchMock);

    let failure: unknown;
    try {
      await requestServerLogout({ ...session, oidcRevocationEndpoint: REVOCATION_URL });
    } catch (error) {
      failure = error;
    }

    expect(failure).toHaveProperty("message", "OIDC revocation failed (HTTP 503)");
    expect((failure as Error).cause).toHaveProperty("message", expect.stringContaining("temporarily unavailable"));
  });

  it("sends a bounded authenticated request and accepts a successful response", async () => {
    const fetchMock = vi.fn().mockResolvedValue(exactResponse(LOGOUT_URL, null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await requestServerLogout(session);

    expect(fetchMock).toHaveBeenCalledWith(
      "https://backend.telecrypt.io/_matrix/client/v3/logout",
      expect.objectContaining({
        method: "POST",
        headers: { Authorization: "Bearer secret-access-token" },
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("does not follow a logout redirect carrying the bearer token", async () => {
    const fetchMock = vi.fn().mockResolvedValue(exactResponse(
      "https://backend.telecrypt.io/redirect",
      null,
      { status: 302 },
    ));
    vi.stubGlobal("fetch", fetchMock);

    await expect(requestServerLogout(session)).rejects.toThrow("server logout redirected unexpectedly");

    expect(fetchMock).toHaveBeenCalledWith(
      "https://backend.telecrypt.io/_matrix/client/v3/logout",
      expect.objectContaining({ redirect: "manual", signal: expect.any(AbortSignal) }),
    );
  });

  it("bounds cleanup of an acquired redirected response body", async () => {
    vi.useFakeTimers();
    try {
      let cancelCalled = false;
      const body = new ReadableStream<Uint8Array>({
        cancel: () => {
          cancelCalled = true;
          return new Promise<void>(() => {});
        },
      });
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exactResponse(
        "https://backend.telecrypt.io/redirect",
        body,
        { status: 302 },
      )));

      const pending = requestServerLogout(session);
      const failure = expect(pending).rejects.toThrow("server logout redirected unexpectedly");
      await vi.advanceTimersByTimeAsync(0);
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;
      expect(cancelCalled).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("surfaces HTTP failure without exposing the token", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exactResponse(LOGOUT_URL, null, { status: 401 })));

    await expect(requestServerLogout(session)).rejects.toThrow("server logout failed (HTTP 401)");
    await expect(requestServerLogout(session)).rejects.not.toThrow("secret-access-token");
  });

  it("retains a non-success response body as the failure cause", async () => {
    const body = {
      errcode: "M_LIMIT_EXCEEDED",
      error: "retry later",
      details: "access_token=server-secret contact alice@example.test",
    };
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exactResponse(LOGOUT_URL, JSON.stringify(body), { status: 429 })));

    let failure: unknown;
    try {
      await requestServerLogout({ ...session, refreshToken: undefined });
    } catch (error) {
      failure = error;
    }

    expect(failure).toHaveProperty("message", "server logout failed (HTTP 429)");
    expect((failure as Error).cause).toBeInstanceOf(Error);
    expect(((failure as Error).cause as Error).message).toContain("M_LIMIT_EXCEEDED");
    expect(((failure as Error).cause as Error).message).toContain("retry later");
    expect(((failure as Error).cause as Error).message).not.toContain("server-secret");
    expect(((failure as Error).cause as Error).message).not.toContain("alice@example.test");
  });

  it("retains malformed response JSON as the parse cause", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exactResponse(LOGOUT_URL, "not-json", { status: 200 })));

    let failure: unknown;
    try {
      await requestServerLogout(session);
    } catch (error) {
      failure = error;
    }

    expect(failure).toHaveProperty("message", "server logout response is not valid JSON");
    expect(failure).toHaveProperty("cause");
    expect((failure as Error).cause).toBeInstanceOf(AggregateError);
    expect(((failure as Error).cause as AggregateError).errors[0]).toBeInstanceOf(SyntaxError);
    expect(((failure as Error).cause as AggregateError).errors[1]).toMatchObject({
      message: "server logout response body: not-json",
    });
  });

  it("treats Matrix's explicit unknown token as final only when no refresh grant remains", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      exactResponse(LOGOUT_URL, JSON.stringify({ errcode: "M_UNKNOWN_TOKEN", error: "unknown token" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }),
    ));

    await expect(requestServerLogout({
      homeserver: session.homeserver,
      accessToken: session.accessToken,
      oidcIssuer: session.oidcIssuer,
    })).resolves.toBeUndefined();
  });

  it("refreshes a live grant, persists rotated credentials, and revokes the latest access token", async () => {
    const unknown = exactResponse(LOGOUT_URL, JSON.stringify({ errcode: "M_UNKNOWN_TOKEN" }), {
      status: 401,
      headers: { "content-type": "application/json" },
    });
    const refreshed = exactResponse(TOKEN_URL, JSON.stringify({
      access_token: "latest-access-token",
      refresh_token: "latest-refresh-token",
    }), { status: 200, headers: { "content-type": "application/json" } });
    const success = exactResponse(LOGOUT_URL, null, { status: 200 });
    const fetchMock = vi.fn().mockResolvedValueOnce(unknown).mockResolvedValueOnce(refreshed).mockResolvedValueOnce(success);
    const onRefreshed = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await requestServerLogout(session, undefined, undefined, onRefreshed);

    expect(onRefreshed).toHaveBeenCalledWith(expect.objectContaining({
      accessToken: "latest-access-token",
      refreshToken: "latest-refresh-token",
    }));
    expect(fetchMock).toHaveBeenNthCalledWith(3, LOGOUT_URL, expect.objectContaining({
      headers: { Authorization: "Bearer latest-access-token" },
    }));
  });

  it("accepts invalid_grant only after an exact unknown access-token response", async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(exactResponse(LOGOUT_URL, JSON.stringify({ errcode: "M_UNKNOWN_TOKEN" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      }))
      .mockResolvedValueOnce(exactResponse(TOKEN_URL, JSON.stringify({ error: "invalid_grant" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(requestServerLogout(session)).resolves.toBeUndefined();
  });

  it("aborts a hung request at the caller-provided deadline", async () => {
    const fetchMock = vi.fn((_url: string, init: RequestInit) => new Promise<never>((_resolve, reject) => {
      init.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
    }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(requestServerLogout(session, 1)).rejects.toThrow("server logout request timed out");
    expect((fetchMock.mock.calls[0]?.[1] as RequestInit).signal?.aborted).toBe(true);
  });

  it("bounds a fetch implementation that ignores logout cancellation", async () => {
    vi.useFakeTimers();
    try {
      const fetchMock = vi.fn(() => new Promise<Response>(() => {}));
      vi.stubGlobal("fetch", fetchMock);
      const pending = requestServerLogout(session, 10);
      const failure = expect(pending).rejects.toThrow("server logout request timed out");
      await vi.advanceTimersByTimeAsync(10);
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;
      expect((fetchMock.mock.calls[0]?.[1] as RequestInit).signal?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("abort-races a logout response body and bounds reader cancellation", async () => {
    vi.useFakeTimers();
    try {
      let cancelCalled = false;
      const body = new ReadableStream<Uint8Array>({
        cancel: () => {
          cancelCalled = true;
          return new Promise<void>(() => {});
        },
      });
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exactResponse(LOGOUT_URL, body, { status: 200 })));

      const pending = requestServerLogout(session, 10);
      const failure = expect(pending).rejects.toThrow("server logout request timed out");
      await vi.advanceTimersByTimeAsync(10);
      await failure;
      expect(cancelCalled).toBe(true);

      await vi.advanceTimersByTimeAsync(5_000);
      expect(vi.getTimerCount()).toBe(0);
      const releasedReader = body.getReader();
      releasedReader.releaseLock();
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not publish a refresh response after the bounded cleanup owner is gone", async () => {
    vi.useFakeTimers();
    try {
      const unknown = exactResponse(LOGOUT_URL, JSON.stringify({ errcode: "M_UNKNOWN_TOKEN" }), {
        status: 401,
        headers: { "content-type": "application/json" },
      });
      let resolveRefresh!: (response: Response) => void;
      const fetchMock = vi.fn()
        .mockResolvedValueOnce(unknown)
        .mockImplementationOnce(() => new Promise<Response>((resolve) => { resolveRefresh = resolve; }));
      const onRefreshed = vi.fn();
      vi.stubGlobal("fetch", fetchMock);

      const pending = requestServerLogout(session, 10, undefined, onRefreshed);
      for (let index = 0; index < 5; index += 1) await Promise.resolve();
      await vi.advanceTimersByTimeAsync(0);
      const failure = expect(pending).rejects.toThrow("server logout request timed out");
      await vi.advanceTimersByTimeAsync(10);
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;

      resolveRefresh(exactResponse(TOKEN_URL, JSON.stringify({ access_token: "too-late" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }));
      await vi.advanceTimersByTimeAsync(0);
      expect(onRefreshed).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("cancels remote revocation and retains local credentials", async () => {
    const dir = fixtureDirectory("telecrypt-logout-cancel");
    const controller = new AbortController();
    writeSession(session, dir);
    const fetchMock = vi.fn((_url: string, init: RequestInit) => new Promise<never>((_resolve, reject) => {
      init.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
    }));
    vi.stubGlobal("fetch", fetchMock);
    const pending = logoutProfile(dir, controller.signal);
    controller.abort(new Error("cancelled by test"));
    await expect(pending).rejects.toThrow("server logout cancelled");
    expect(fs.existsSync(sessionPath(dir))).toBe(true);
    expect((fetchMock.mock.calls[0]?.[1] as RequestInit).signal?.aborted).toBe(true);
  });

  it("consumes a large successful logout response without a diagnostic-size rejection", async () => {
    const body = JSON.stringify({ detail: "x".repeat(64 * 1024 + 1) });
    const fetchMock = vi.fn().mockResolvedValue(exactResponse(LOGOUT_URL, body, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(requestServerLogout(session)).resolves.toBeUndefined();
  });

  it("retains local credentials when remote revocation fails", async () => {
    const dir = fixtureDirectory("telecrypt-logout-test");
    writeSession(session, dir);
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));

    await expect(logoutProfile(dir)).rejects.toThrow("server logout request failed");
    expect(fs.existsSync(sessionPath(dir))).toBe(true);
  });

  it("clears local credentials only after remote revocation succeeds", async () => {
    const dir = fixtureDirectory("telecrypt-logout-test");
    writeSession(session, dir);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(exactResponse(LOGOUT_URL, null, { status: 200 })));

    await expect(logoutProfile(dir)).resolves.toEqual({ hadSession: true, serverLogout: "revoked" });
    expect(fs.existsSync(sessionPath(dir))).toBe(false);
  });

  it("retains an idempotent revoke marker when local cleanup fails", async () => {
    const dir = fixtureDirectory("telecrypt-logout-cleanup-test");
    writeSession(session, dir);
    fs.mkdirSync(cryptoSnapshotPath(dir), { mode: 0o700 });
    const fetchMock = vi.fn().mockResolvedValue(exactResponse(LOGOUT_URL, null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(logoutProfile(dir)).rejects.toThrow();
    expect(fs.existsSync(sessionPath(dir))).toBe(true);
    expect(fs.existsSync(logoutMarkerPath(dir))).toBe(true);

    fs.rmSync(cryptoSnapshotPath(dir), { recursive: true });
    fetchMock.mockRejectedValue(new Error("remote must not be contacted again"));
    await expect(logoutProfile(dir)).resolves.toEqual({ hadSession: true, serverLogout: "revoked" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fs.existsSync(logoutMarkerPath(dir))).toBe(false);
  });

  it("keeps the revoke marker when unexpected private state blocks final cleanup", async () => {
    const dir = fixtureDirectory("telecrypt-logout-extra-state-test");
    const extra = path.join(dir, "unexpected-private-state");
    writeSession(session, dir);
    fs.writeFileSync(extra, "retain until inspected\n", { mode: 0o600 });
    const fetchMock = vi.fn().mockResolvedValue(exactResponse(LOGOUT_URL, null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(logoutProfile(dir)).rejects.toThrow("local cleanup is incomplete");
    expect(fs.existsSync(sessionPath(dir))).toBe(false);
    expect(fs.existsSync(logoutMarkerPath(dir))).toBe(true);
    expect(fs.existsSync(extra)).toBe(true);

    fs.rmSync(extra);
    await expect(logoutProfile(dir)).resolves.toEqual({ hadSession: false, serverLogout: "revoked" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("falls back to direct cleanup when marker persistence fails after revocation", async () => {
    const dir = fixtureDirectory("telecrypt-logout-marker-write-test");
    writeSession(session, dir);
    const fetchMock = vi.fn().mockResolvedValue(exactResponse(LOGOUT_URL, null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const originalRename = fs.renameSync;
    const rename = vi.spyOn(fs, "renameSync").mockImplementation(((from, to) => {
      if (String(to) === logoutMarkerPath(dir) || String(to).endsWith("/logout-complete")) throw new Error("simulated marker write failure");
      return originalRename(from, to);
    }) as typeof fs.renameSync);
    try {
      await expect(logoutProfile(dir)).resolves.toEqual({ hadSession: true, serverLogout: "revoked" });
    } finally {
      rename.mockRestore();
    }
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fs.existsSync(sessionPath(dir))).toBe(false);
    expect(fs.existsSync(logoutMarkerPath(dir))).toBe(false);
  });

  it("does not contact the server when no local session exists", async () => {
    const dir = fixtureDirectory("telecrypt-logout-missing");
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(logoutProfile(dir)).resolves.toEqual({ hadSession: false, serverLogout: "not-needed" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("revokes and clears a token-bearing pending login state", async () => {
    const dir = fixtureDirectory("telecrypt-logout-pending");
    writePendingSessionUnlocked({
      homeserver: session.homeserver,
      deviceId: session.deviceId,
      accessToken: session.accessToken,
      oidcIssuer: session.oidcIssuer,
      refreshToken: session.refreshToken,
      oidcClientId: session.oidcClientId,
      oidcTokenEndpoint: session.oidcTokenEndpoint,
      oidcRevocationEndpoint: session.oidcRevocationEndpoint,
      matrixServerName: session.matrixServerName,
    }, dir);
    const fetchMock = vi.fn().mockResolvedValue(exactResponse(LOGOUT_URL, null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(logoutProfile(dir)).resolves.toEqual({ hadSession: true, serverLogout: "revoked" });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fs.existsSync(pendingSessionPath(dir))).toBe(false);
  });
});
