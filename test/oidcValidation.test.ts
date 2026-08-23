import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as core from "@telecrypt-io/storage/core";
import type { OidcClientConfig } from "@telecrypt-io/storage/core";
import { assertOidcEndpoint, runDeviceCodeLogin, validateOidcMetadata } from "../src/oidc.js";

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
    signingKeys: null,
    ...overrides,
  };
}

describe("CLI OIDC endpoint validation", () => {
  let previousNoBrowser: string | undefined;

  beforeEach(() => {
    previousNoBrowser = process.env.TELECRYPT_IO_STORAGE_NO_BROWSER;
    process.env.TELECRYPT_IO_STORAGE_NO_BROWSER = "1";
  });

  afterEach(() => {
    vi.resetAllMocks();
    if (previousNoBrowser === undefined) delete process.env.TELECRYPT_IO_STORAGE_NO_BROWSER;
    else process.env.TELECRYPT_IO_STORAGE_NO_BROWSER = previousNoBrowser;
  });

  it("accepts the current production endpoint layout", () => {
    expect(validateOidcMetadata(metadata(), HOMESERVER)).toEqual(metadata());
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

  it.each([
    ["issuer", { issuer: "https://accounts.example.test/auth/" }],
    ["authorization endpoint", { authorization_endpoint: "https://accounts.example.test/auth/authorize" }],
    ["device authorization endpoint", { device_authorization_endpoint: "https://accounts.example.test/auth/device" }],
    ["registration endpoint", { registration_endpoint: "https://accounts.example.test/auth/register" }],
    ["token endpoint", { token_endpoint: "https://accounts.example.test/auth/token" }],
    ["JWKS endpoint", { jwks_uri: "https://accounts.example.test/auth/jwks" }],
  ])("rejects a cross-origin %s", (_name, override) => {
    expect(() => validateOidcMetadata(metadata(override), HOMESERVER)).toThrow(/configured homeserver origin|configured OIDC origin/);
  });

  it.each([
    ["outside issuer path", { token_endpoint: "https://backend.telecrypt.io/other/token" }],
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
    expect(discovery).toHaveBeenCalledWith(HOMESERVER);
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
    });
    vi.mocked(core.whoAmI).mockResolvedValue({ userId: "@alice:example.test" });

    const session = await runDeviceCodeLogin(HOMESERVER, { onVerification: verification });

    expect(session).toMatchObject({
      homeserver: HOMESERVER,
      userId: "@alice:example.test",
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
});
