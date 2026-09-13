import { afterEach, describe, expect, it, vi } from "vitest";
import type { ChildProcess } from "node:child_process";
import { spawn } from "node:child_process";
import * as core from "@telecrypt-io/storage/core";
import type { OidcClientConfig } from "@telecrypt-io/storage/core";
import { assertOidcEndpoint, assertTrustedHomeserver, OidcLoginError, runDeviceCodeLogin, tryOpenBrowser } from "../src/oidc.js";

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

function metadataFor(homeserver: string, overrides: Partial<OidcClientConfig> = {}): OidcClientConfig {
  const issuer = `${homeserver}/auth/`;
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

function metadata(overrides: Partial<OidcClientConfig> = {}): OidcClientConfig {
  return metadataFor(HOMESERVER, overrides);
}

describe("CLI OIDC endpoint validation", () => {
  afterEach(() => {
    vi.resetAllMocks();
    vi.unstubAllGlobals();
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

  it("rejects a non-loopback HTTP homeserver before discovery", async () => {
    await expect(runDeviceCodeLogin("http://accounts.example.test", { onVerification: vi.fn() })).rejects.toThrow(
      "homeserver is not a supported TeleCrypt deployment",
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
    "https://backend.preview.telecrypt.io",
    "https://backend-stage.telecrypt.io",
    "https://evil.example",
    "https://backend.telecrypt.io:443",
  ])("rejects a homeserver outside the exact deployment allowlist: %s", (homeserver) => {
    expect(() => assertTrustedHomeserver(homeserver)).toThrow(/supported TeleCrypt deployment/u);
  });

  it("binds a discovered issuer to the selected TeleCrypt deployment", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata({ issuer: "https://accounts.example.test/auth/" }));

    await expect(runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() })).rejects.toThrow(
      /configured OIDC origin/u,
    );
    expect(core.registerClient).not.toHaveBeenCalled();
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

  it("uses verification URLs on the trusted issuer path without filtering their query spelling", async () => {
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(metadata());
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: "https://backend.telecrypt.io/auth/device?redirect_uri=https%3A%2F%2Fevil.example",
      expires_in: 600,
      interval: 1,
    });
    vi.mocked(core.waitForDeviceCodeLogin).mockResolvedValue({
      access_token: "access-token",
      refresh_token: "refresh-token",
      token_type: "Bearer",
      scope: "urn:matrix:client:api:* urn:matrix:client:device:DEVICE123",
    });
    vi.mocked(core.whoAmI).mockImplementation(async () => ({
      userId: "@alice:telecrypt.io",
      deviceId: vi.mocked(core.startDeviceCodeLogin).mock.calls[0]?.[2] ?? null,
    }));
    const onVerification = vi.fn();

    await expect(runDeviceCodeLogin(HOMESERVER, { onVerification, openBrowser: false })).resolves.toMatchObject({
      userId: "@alice:telecrypt.io",
      accessToken: "access-token",
    });
    expect(onVerification).toHaveBeenCalledWith(expect.objectContaining({
      verificationUri: "https://backend.telecrypt.io/auth/device?redirect_uri=https%3A%2F%2Fevil.example",
    }));
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
    expect(core.whoAmI).toHaveBeenCalledWith(
      HOMESERVER,
      "access-token",
      "telecrypt.io",
      expect.anything(),
    );
  });

  it("passes the stage Matrix server name independently of the backend hostname", async () => {
    const stageHomeserver = "https://backend.stage.telecrypt.io";
    const stageMetadata = metadataFor(stageHomeserver);
    vi.mocked(core.discoverOidcIssuer).mockResolvedValue(stageMetadata);
    vi.mocked(core.registerClient).mockResolvedValue("client-id");
    vi.mocked(core.startDeviceCodeLogin).mockResolvedValue({
      device_code: "device-code",
      user_code: "ABC-123",
      verification_uri: `${stageHomeserver}/auth/device`,
      expires_in: 600,
      interval: 1,
    });
    vi.mocked(core.waitForDeviceCodeLogin).mockResolvedValue({
      access_token: "access-token",
      refresh_token: "refresh-token",
      token_type: "Bearer",
    });
    vi.mocked(core.whoAmI).mockImplementation(async () => ({
      userId: "@alice:stage.telecrypt.io",
      deviceId: vi.mocked(core.startDeviceCodeLogin).mock.calls.at(-1)?.[2] ?? null,
    }));

    await runDeviceCodeLogin(stageHomeserver, { onVerification: vi.fn(), openBrowser: false });

    expect(core.whoAmI).toHaveBeenCalledWith(
      stageHomeserver,
      "access-token",
      "stage.telecrypt.io",
      expect.anything(),
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

  it("retains identity verification failures as causes", async () => {
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
    const identityFailure = new Error("whoami transport failed");
    vi.mocked(core.whoAmI).mockRejectedValue(identityFailure);

    let failure: unknown;
    try {
      await runDeviceCodeLogin(HOMESERVER, { onVerification: vi.fn() });
    } catch (error) {
      failure = error;
    }

    expect(failure).toHaveProperty("message", "whoami transport failed");
    expect(failure).toHaveProperty("cause", identityFailure);
  });
});
