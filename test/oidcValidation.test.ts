import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChildProcess } from "node:child_process";
import { spawn } from "node:child_process";
import * as core from "@telecrypt-io/storage/core";
import type { OidcClientConfig } from "@telecrypt-io/storage/core";
import { assertOidcEndpoint, assertTrustedHomeserver, OidcLoginError, runDeviceCodeLogin, tryOpenBrowser, validateOidcMetadata } from "../src/oidc.js";

vi.mock("node:child_process", () => ({ spawn: vi.fn() }));

vi.mock("@telecrypt-io/storage/core", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@telecrypt-io/storage/core")>();
  return {
    ...actual,
    discoverOidcIssuer: vi.fn(),
    registerClient: vi.fn(),
    startDeviceCodeLogin: vi.fn(),
    waitForDeviceCodeLogin: vi.fn(),
    whoAmI: vi.fn(),
  };
});

const HOMESERVER = "https://backend.telecrypt.io";

function metadata(overrides: Partial<OidcClientConfig> = {}): OidcClientConfig {
  const issuer = "https://backend.telecrypt.io/auth/";
  return {
    issuer,
    authorization_endpoint: `${issuer}authorize`,
    device_authorization_endpoint: `${issuer}device`,
    registration_endpoint: `${issuer}register`,
    token_endpoint: `${issuer}token`,
    revocation_endpoint: `${issuer}revoke`,
    jwks_uri: `${issuer}jwks`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
    code_challenge_methods_supported: ["S256"],
    ...overrides,
  };
}

describe("CLI OIDC endpoint validation", () => {
  afterEach(() => {
    vi.resetAllMocks();
    vi.unstubAllGlobals();
  });

  it("accepts the current production endpoint layout", () => {
    expect(validateOidcMetadata(metadata(), HOMESERVER)).toEqual(metadata());
  });

  it("accepts an issuer without an OIDC revocation endpoint", () => {
    const withoutRevocation = metadata();
    delete (withoutRevocation as Partial<OidcClientConfig>).revocation_endpoint;
    expect(validateOidcMetadata(withoutRevocation, HOMESERVER)).toEqual(withoutRevocation);
  });

  it("consumes an asynchronous browser launcher failure", () => {
    const child = {
      once: vi.fn((event: string, callback: () => void) => {
        if (event === "error") callback();
        return child;
      }),
      unref: vi.fn(),
    } as unknown as ChildProcess;
    vi.mocked(spawn).mockReturnValue(child);

    expect(() => tryOpenBrowser("https://backend.telecrypt.io/auth/device")).not.toThrow();
    expect(child.once).toHaveBeenCalledWith("error", expect.any(Function));
  });

  it("accepts a local homeserver with the normal trailing slash normalization", () => {
    const localHomeserver = "http://localhost:8008";
    const localMetadata = metadata({
      issuer: "http://localhost:8008/auth/",
      authorization_endpoint: "http://localhost:8008/auth/authorize",
      device_authorization_endpoint: "http://localhost:8008/auth/device",
      registration_endpoint: "http://localhost:8008/auth/register",
      token_endpoint: "http://localhost:8008/auth/token",
      revocation_endpoint: "http://localhost:8008/auth/revoke",
      jwks_uri: "http://localhost:8008/auth/jwks",
    });

    expect(validateOidcMetadata(localMetadata, localHomeserver)).toEqual(localMetadata);
  });

  it("rejects a non-loopback HTTP homeserver before discovery", async () => {
    await expect(runDeviceCodeLogin("http://accounts.example.test", { onVerification: vi.fn() })).rejects.toThrow(
      "must use HTTPS except for the exact loopback host",
    );
    expect(core.discoverOidcIssuer).not.toHaveBeenCalled();
  });

  it.each(["https://backend.telecrypt.io", "http://localhost:8008", "http://127.0.0.1:8008", "http://[::1]:8008"])(
    "accepts only HTTPS or exact loopback homeservers: %s",
    (homeserver) => {
      expect(assertTrustedHomeserver(homeserver)).toBe(homeserver);
    },
  );

  it.each([
    ["issuer", { issuer: "https://accounts.example.test/auth/" }],
    ["authorization endpoint", { authorization_endpoint: "https://accounts.example.test/auth/authorize" }],
    ["device authorization endpoint", { device_authorization_endpoint: "https://accounts.example.test/auth/device" }],
    ["registration endpoint", { registration_endpoint: "https://accounts.example.test/auth/register" }],
    ["token endpoint", { token_endpoint: "https://accounts.example.test/auth/token" }],
    ["revocation endpoint", { revocation_endpoint: "https://accounts.example.test/auth/revoke" }],
    ["JWKS endpoint", { jwks_uri: "https://accounts.example.test/auth/jwks" }],
  ])("rejects a cross-origin %s", (_name, override) => {
    expect(() => validateOidcMetadata(metadata(override), HOMESERVER)).toThrow(/configured homeserver origin|configured OIDC origin/);
  });

  it.each([
    ["outside issuer path", { token_endpoint: "https://backend.telecrypt.io/other/token" }],
    ["outside issuer revocation path", { revocation_endpoint: "https://backend.telecrypt.io/other/revoke" }],
    ["with a query", { registration_endpoint: "https://backend.telecrypt.io/auth/register?next=https://evil.example" }],
    ["with credentials", { token_endpoint: "https://attacker:secret@backend.telecrypt.io/auth/token" }],
  ])("rejects an endpoint %s", (_name, override) => {
    expect(() => validateOidcMetadata(metadata(override), HOMESERVER)).toThrow();
  });

  it("rejects a persisted refresh endpoint before it can be used", () => {
    expect(() => assertOidcEndpoint("https://evil.example/token", HOMESERVER, "OIDC token endpoint")).toThrow(
      /configured OIDC origin/,
    );
    expect(assertOidcEndpoint("https://backend.telecrypt.io/auth/token", HOMESERVER, "OIDC token endpoint")).toBe(
      "https://backend.telecrypt.io/auth/token",
    );
  });

  it("allows the issuer-provided verification code query on the trusted origin", () => {
    const issuer = new URL("https://backend.telecrypt.io/auth/");
    expect(
      assertOidcEndpoint(
        "https://backend.telecrypt.io/auth/device?user_code=ABC",
        HOMESERVER,
        "OIDC verification URI",
        issuer,
        true,
      ),
    ).toBe("https://backend.telecrypt.io/auth/device?user_code=ABC");
  });

  it("rejects a same-origin verification URL that carries an open-redirect parameter", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device?redirect_uri=https%3A%2F%2Fevil.example",
      expires_in: 600,
      interval: 1,
    });

    await expect(runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() })).rejects.toThrow(
      "unsafe redirect parameter",
    );
  });

  it("rejects an oversized provider verification URI before exposing it", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    const verification = vi.fn();
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: `https://backend.telecrypt.io/auth/${"a".repeat(2048)}`,
      expires_in: 600,
      interval: 1,
    });

    await expect(runDeviceCodeLogin(HOMESERVER, { onVerification: verification })).rejects.toThrow(
      "OIDC verification URI exceeds maximum length",
    );
    expect(verification).not.toHaveBeenCalled();
  });

  it("fails closed when OIDC discovery does not finish before its deadline", async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(core.discoverOidcIssuer).mockImplementation((_homeserver, signal) =>
        new Promise<OidcClientConfig>((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
        }),
      );
      const pending = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() });
      const failure = expect(pending).rejects.toThrow("OIDC discovery timed out");
      await vi.advanceTimersByTimeAsync(30_001);
      await failure;
      expect((vi.mocked(core.discoverOidcIssuer).mock.calls[0]?.[1] as AbortSignal)?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("does not invoke a scheduled OIDC operation after cancellation wins the race", async () => {
    const controller = new AbortController();
    const discovery = vi.mocked(core.discoverOidcIssuer);
    const pending = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }, controller.signal);
    controller.abort(new Error("cancelled before discovery starts"));

    await expect(pending).rejects.toThrow("OIDC operation cancelled");
    expect(discovery).not.toHaveBeenCalled();
  });

  it("restores the temporary OIDC window shim when discovery ignores cancellation", async () => {
    vi.useFakeTimers();
    const hadWindow = Object.prototype.hasOwnProperty.call(globalThis, "window");
    const globalObject = globalThis as unknown as { window?: unknown };
    const previousWindow = globalObject.window;
      try {
      vi.mocked(core.discoverOidcIssuer).mockImplementation(() => new Promise<OidcClientConfig>(() => {}));
      const pending = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() });
      const failure = expect(pending).rejects.toThrow("OIDC discovery timed out");
      await vi.advanceTimersByTimeAsync(30_000);
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;
      expect(Object.prototype.hasOwnProperty.call(globalThis, "window")).toBe(hadWindow);
      expect(globalObject.window).toBe(previousWindow);
    } finally {
      vi.useRealTimers();
      if (hadWindow) globalObject.window = previousWindow;
      else delete globalObject.window;
    }
  });

  it("does not overwrite a replacement window owned by another invocation", async () => {
    const globalObject = globalThis as unknown as { window?: unknown };
    const hadWindow = Object.prototype.hasOwnProperty.call(globalObject, "window");
    const previousWindow = globalObject.window;
    const originalWindow = {};
    const replacementWindow = {};
    const controller = new AbortController();
    try {
      globalObject.window = originalWindow;
      vi.mocked(core.discoverOidcIssuer).mockImplementation((_homeserver, signal) =>
        new Promise<OidcClientConfig>((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
        }),
      );
      const pending = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }, controller.signal);
      await vi.waitFor(() => expect(core.discoverOidcIssuer).toHaveBeenCalled());

      globalObject.window = replacementWindow;
      controller.abort(new Error("cancelled by test"));
      await expect(pending).rejects.toThrow("OIDC operation cancelled");
      expect(globalObject.window).toBe(replacementWindow);
    } finally {
      if (hadWindow) globalObject.window = previousWindow;
      else delete globalObject.window;
    }
  });

  it("keeps one temporary window shim alive for concurrent discovery owners", async () => {
    const globalObject = globalThis as unknown as { window?: unknown };
    const hadWindow = Object.prototype.hasOwnProperty.call(globalThis, "window");
    const previousWindow = globalObject.window;
    let resolveFirst!: (value: OidcClientConfig) => void;
    let resolveSecond!: (value: OidcClientConfig) => void;
    const observedWindows: unknown[] = [];
    const firstController = new AbortController();
    const secondController = new AbortController();
    let first: Promise<unknown> | undefined;
    let second: Promise<unknown> | undefined;
    try {
      if (hadWindow) delete globalObject.window;
      vi.mocked(core.discoverOidcIssuer).mockImplementation(() => {
        observedWindows.push(globalObject.window);
        return new Promise<OidcClientConfig>((resolve) => {
          if (observedWindows.length === 1) resolveFirst = resolve;
          else resolveSecond = resolve;
        });
      });
      vi.mocked(core.registerClient).mockRejectedValue(new Error("stop after discovery"));

      first = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }, firstController.signal);
      second = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }, secondController.signal);
      await vi.waitFor(() => expect(observedWindows).toHaveLength(2));
      expect(observedWindows[0]).toBe(observedWindows[1]);
      const shim = observedWindows[0];

      resolveFirst(metadata());
      await expect(first).rejects.toThrow("stop after discovery");
      expect(globalObject.window).toBe(shim);

      resolveSecond(metadata());
      await expect(second).rejects.toThrow("stop after discovery");
      expect(Object.prototype.hasOwnProperty.call(globalObject, "window")).toBe(false);
    } finally {
      firstController.abort(new Error("test cleanup"));
      secondController.abort(new Error("test cleanup"));
      await Promise.allSettled([first, second].filter((value): value is Promise<unknown> => value !== undefined));
      if (hadWindow) globalObject.window = previousWindow;
      else delete globalObject.window;
    }
  });

  it("joins SDK cancellation before returning the OIDC deadline", async () => {
    vi.useFakeTimers();
    try {
      let cancellationJoined = false;
      vi.mocked(core.discoverOidcIssuer).mockImplementation((_homeserver, signal) =>
        new Promise<OidcClientConfig>((_resolve, reject) => {
          signal?.addEventListener("abort", () => {
            setTimeout(() => {
              cancellationJoined = true;
              reject(new Error("transport stopped"));
            }, 5);
          }, { once: true });
        }),
      );
      const pending = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() });
      const failure = expect(pending).rejects.toThrow("OIDC discovery timed out");
      await vi.advanceTimersByTimeAsync(30_010);
      await failure;
      expect(cancellationJoined).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("bounds an OIDC operation that ignores cancellation", async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(core.discoverOidcIssuer).mockImplementation(() => new Promise<OidcClientConfig>(() => {}));
      const pending = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() });
      const failure = expect(pending).rejects.toThrow("OIDC discovery timed out");
      await vi.advanceTimersByTimeAsync(30_000);
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;
    } finally {
      vi.useRealTimers();
    }
  });

  it("passes an AbortSignal to the SDK without replacing the global fetch", async () => {
    const originalFetch = globalThis.fetch;
    let receivedSignal: AbortSignal | undefined;
    vi.mocked(core.discoverOidcIssuer).mockImplementation(async (_homeserver, signal) => {
      receivedSignal = signal;
      expect(globalThis.fetch).toBe(originalFetch);
      return metadata({ issuer: "https://accounts.example.test/auth/" });
    });

    await expect(runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() })).rejects.toThrow(
      /configured homeserver origin|configured OIDC origin/,
    );
    expect(receivedSignal).toBeInstanceOf(AbortSignal);
    expect(globalThis.fetch).toBe(originalFetch);
  });

  it("fails closed when device approval polling exceeds its deadline", async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
      vi.mocked(core.registerClient).mockResolvedValue("client-id");
      vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
        device_code: "device-code",
        user_code: "ABC-123",
        verification_uri: "https://backend.telecrypt.io/auth/device",
        expires_in: 600,
        interval: 1,
      });
      vi.mocked(core.waitForDeviceCodeLogin).mockImplementation((_metadata, _clientId, _session, signal) =>
        new Promise<Awaited<ReturnType<typeof core.waitForDeviceCodeLogin>>>((_resolve, reject) => {
          signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
        }),
      );
      const pending = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() });
      const failure = expect(pending).rejects.toThrow("OIDC approval timed out");
      await vi.advanceTimersByTimeAsync(5 * 60_000 + 1);
      await failure;
      expect((vi.mocked(core.waitForDeviceCodeLogin).mock.calls[0]?.[3] as AbortSignal)?.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("bounds an OIDC approval response-body reader that ignores cancellation", async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
      vi.mocked(core.registerClient).mockResolvedValue("client-id");
      vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
        device_code: "device-code",
        user_code: "ABC-123",
        verification_uri: "https://backend.telecrypt.io/auth/device",
        expires_in: 600,
        interval: 1,
      });
      let approvalSignal!: AbortSignal;
      vi.mocked(core.waitForDeviceCodeLogin).mockImplementation((_metadata, _clientId, _session, signal) => {
        approvalSignal = signal!;
        return new Promise<Awaited<ReturnType<typeof core.waitForDeviceCodeLogin>>>(() => {});
      });

      const pending = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() });
      const failure = expect(pending).rejects.toThrow("OIDC approval timed out");
      await vi.advanceTimersByTimeAsync(5 * 60_000);
      await vi.advanceTimersByTimeAsync(5_000);
      await failure;
      expect(approvalSignal.aborted).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("propagates caller cancellation to SDK approval polling", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device",
      expires_in: 600,
      interval: 1,
    });
    vi.mocked(core.waitForDeviceCodeLogin).mockImplementation((_metadata, _clientId, _session, signal) =>
      new Promise<Awaited<ReturnType<typeof core.waitForDeviceCodeLogin>>>((_resolve, reject) => {
        signal?.addEventListener("abort", () => reject(signal.reason), { once: true });
      }),
    );
    const controller = new AbortController();
    const pending = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }, controller.signal);
    await vi.waitFor(() => expect(core.waitForDeviceCodeLogin).toHaveBeenCalled());
    controller.abort(new Error("cancelled by test"));
    await expect(pending).rejects.toThrow("OIDC operation cancelled");
    expect((vi.mocked(core.waitForDeviceCodeLogin).mock.calls[0]?.[3] as AbortSignal)?.aborted).toBe(true);
  });

  it("retains a token issued while approval cancellation is being joined", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device",
      expires_in: 600,
      interval: 1,
    });
    let resolveApproval!: (value: Awaited<ReturnType<typeof core.waitForDeviceCodeLogin>>) => void;
    vi.mocked(core.waitForDeviceCodeLogin).mockImplementation(() =>
      new Promise((resolve) => { resolveApproval = resolve; }),
    );
    const controller = new AbortController();
    const pending = runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }, controller.signal);
    await vi.waitFor(() => expect(core.waitForDeviceCodeLogin).toHaveBeenCalled());
    controller.abort(new Error("cancelled by test"));
    resolveApproval({ access_token: "late-access", refresh_token: "late-refresh", token_type: "Bearer" });

    const error = await pending.catch((value: unknown) => value);
    expect(error).toBeInstanceOf(OidcLoginError);
    expect((error as OidcLoginError).pendingSession).toMatchObject({
      accessToken: "late-access",
      refreshToken: "late-refresh",
      matrixServerName: "telecrypt.io",
    });
  });

  it("does not start discovery after caller cancellation", async () => {
    const controller = new AbortController();
    controller.abort(new Error("cancelled before login"));

    await expect(
      runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }, controller.signal),
    ).rejects.toThrow("OIDC operation cancelled");
    expect(core.discoverOidcIssuer).not.toHaveBeenCalled();
  });

  it("rejects an oversized provider user code before exposing it", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    const verification = vi.fn();
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "A".repeat(257),
      verification_uri: "https://backend.telecrypt.io/auth/device",
      expires_in: 600,
      interval: 1,
    });

    await expect(runDeviceCodeLogin(HOMESERVER, { onVerification: verification })).rejects.toThrow(
      "OIDC user code exceeds maximum length",
    );
    expect(verification).not.toHaveBeenCalled();
  });

  it("rejects a malformed provider user code before exposing it", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    const verification = vi.fn();
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC/123",
      verification_uri: "https://backend.telecrypt.io/auth/device",
      expires_in: 600,
      interval: 1,
    });

    await expect(runDeviceCodeLogin(HOMESERVER, { onVerification: verification })).rejects.toThrow(
      "OIDC user code contains unsupported characters",
    );
    expect(verification).not.toHaveBeenCalled();
  });

  it("exposes only an allowlisted provider error code", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device",
      expires_in: 600,
      interval: 1,
    });
    vi.mocked(core.waitForDeviceCodeLogin).mockResolvedValue({
      error: "invalid_grant",
      error_description: "provider-controlled detail",
    });

    const error = await runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(Error);
    const message = (error as Error).message;
    expect(message).toContain("invalid_grant");
    expect(message).toBe("device login was not approved (invalid_grant)");
  });

  it("uses a generic provider error for an unallowlisted code or description", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device",
      expires_in: 600,
      interval: 1,
    });
    vi.mocked(core.waitForDeviceCodeLogin).mockResolvedValue({
      error: "provider_private_code\nsecret",
      error_description: "provider detail",
    });

    const error = await runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }).catch((err: unknown) => err);
    expect((error as Error).message).toBe("device login was not approved");
  });

  it.each([
    ["issuer", { issuer: "https://accounts.example.test/auth/" }],
    ["registration endpoint", { registration_endpoint: "https://accounts.example.test/auth/register" }],
    ["token endpoint", { token_endpoint: "https://accounts.example.test/auth/token" }],
  ])("blocks %s before dynamic registration", async (_name, override) => {
    const discovery = vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata(override));
    const registration = vi.mocked(core.registerClient);

    await expect(
      runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }),
    ).rejects.toThrow(/configured homeserver origin|configured OIDC origin/);
    expect(discovery.mock.calls[0]?.[0]).toBe(HOMESERVER);
    expect(discovery.mock.calls[0]?.[1]).toBeInstanceOf(AbortSignal);
    expect(registration).not.toHaveBeenCalled();
  });

  it("blocks an untrusted verification redirect before exposing it or polling", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    const start = vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://accounts.example.test/auth/device",
      expires_in: 600,
      interval: 1,
    });
    const poll = vi.mocked(core.waitForDeviceCodeLogin);

    await expect(
      runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }),
    ).rejects.toThrow(/configured OIDC origin/);
    expect(start).toHaveBeenCalled();
    expect(poll).not.toHaveBeenCalled();
  });

  it("rejects an invalid dynamic client identifier before device authorization", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client id with spaces");

    await expect(runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() })).rejects.toThrow(
      "OIDC client ID is invalid",
    );
    expect(core.startDeviceCodeLogin).not.toHaveBeenCalled();
  });

  it.each([
    ["access token", { access_token: "access token", refresh_token: "refresh-token" }, "OIDC access token is invalid"],
    ["refresh token", { access_token: "access-token", refresh_token: "refresh\n token" }, "OIDC refresh token is invalid"],
  ])("rejects an invalid %s before identity verification", async (_name, tokens, message) => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device",
      expires_in: 600,
      interval: 1,
    });
    vi.mocked(core.waitForDeviceCodeLogin).mockResolvedValue({
      access_token: tokens.access_token ?? "access-token",
      refresh_token: tokens.refresh_token ?? "refresh-token",
      token_type: "Bearer",
    });

    await expect(runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() })).rejects.toThrow(message);
    expect(core.whoAmI).not.toHaveBeenCalled();
  });

  it("rejects an invalid user identifier before creating a session", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device",
      expires_in: 600,
      interval: 1,
    });
    vi.mocked(core.waitForDeviceCodeLogin).mockResolvedValue({
      access_token: "access-token",
      refresh_token: "refresh-token",
      token_type: "Bearer",
    });
    vi.mocked(core.whoAmI).mockResolvedValue({ userId: "not-a-matrix-user", deviceId: "DEVICE" });

    const error = await runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }).catch((err: unknown) => err);
    expect(error).toBeInstanceOf(OidcLoginError);
    expect((error as OidcLoginError).pendingSession).toMatchObject({
      homeserver: HOMESERVER,
      accessToken: "access-token",
      refreshToken: "refresh-token",
    });
    expect((error as Error).message).toContain(
      "OIDC identity verification failed",
    );
  });

  it("completes the current device-code flow with trusted metadata and URLs", async () => {
    const verification = vi.fn();
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device",
      verification_uri_complete: "https://backend.telecrypt.io/auth/device?user_code=ABC-123",
      expires_in: 600,
      interval: 1,
    });
    vi.mocked(core.waitForDeviceCodeLogin).mockResolvedValue({
      access_token: "access-token",
      refresh_token: "refresh-token",
      token_type: "Bearer",
    });
    vi.mocked(core.whoAmI).mockImplementation(async () => {
      const requestedDeviceId = vi.mocked(core.startDeviceCodeLogin).mock.calls.at(-1)?.[2];
      if (!requestedDeviceId) throw new Error("test did not capture the requested device ID");
      return { userId: "@alice:telecrypt.io", deviceId: requestedDeviceId };
    });

    const session = await runDeviceCodeLogin(HOMESERVER, { onVerification: verification });

    expect(session).toMatchObject({
      homeserver: HOMESERVER,
      userId: "@alice:telecrypt.io",
      accessToken: "access-token",
      refreshToken: "refresh-token",
      oidcClientId: "client-id",
      oidcTokenEndpoint: "https://backend.telecrypt.io/auth/token",
    });
    expect(verification).toHaveBeenCalledWith({
      verificationUri: "https://backend.telecrypt.io/auth/device",
      verificationUriComplete: "https://backend.telecrypt.io/auth/device?user_code=ABC-123",
      userCode: "ABC-123",
    });
  });

  it("rejects a valid canonical MXID from a server outside the trusted TeleCrypt topology", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device",
      expires_in: 600,
      interval: 1,
    });
    vi.mocked(core.waitForDeviceCodeLogin).mockResolvedValue({
      access_token: "access-token",
      refresh_token: "refresh-token",
      token_type: "Bearer",
    });
    vi.mocked(core.whoAmI).mockImplementation(async () => ({
      userId: "@alice:other.example",
      deviceId: vi.mocked(core.startDeviceCodeLogin).mock.calls.at(-1)?.[2] ?? null,
    }));

    await expect(runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() })).rejects.toThrow(
      "OIDC identity does not match the configured TeleCrypt deployment",
    );
  });

  it("retains issued credentials when cancellation arrives after token polling", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device",
      expires_in: 600,
      interval: 1,
    });
    const controller = new AbortController();
    vi.mocked(core.waitForDeviceCodeLogin).mockResolvedValue({
      access_token: "access-token", refresh_token: "refresh-token", token_type: "Bearer",
    });
    vi.mocked(core.whoAmI).mockImplementation(async () => {
      controller.abort(new Error("cancelled after token issuance"));
      throw new Error("identity request interrupted");
    });

    const error = await runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() }, controller.signal).catch((value: unknown) => value);
    expect(error).toBeInstanceOf(OidcLoginError);
    expect((error as OidcLoginError).pendingSession).toMatchObject({
      accessToken: "access-token",
      refreshToken: "refresh-token",
      oidcClientId: "client-id",
    });
    expect(core.whoAmI).toHaveBeenCalled();
  });

  it("rejects a whoami response that omits the requested device identity", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device",
      expires_in: 600,
      interval: 1,
    });
    vi.mocked(core.waitForDeviceCodeLogin).mockResolvedValue({
      access_token: "access-token",
      refresh_token: "refresh-token",
      token_type: "Bearer",
    });
    vi.mocked(core.whoAmI).mockResolvedValue({ userId: "@alice:telecrypt.io", deviceId: null });

    await expect(runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() })).rejects.toThrow(
      "OIDC identity verification failed",
    );
  });
});
