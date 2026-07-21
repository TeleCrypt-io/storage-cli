/**
 * CLI-only OIDC/MAS adapter: device-code login (RFC 8628) against a
 * homeserver's delegated auth service (MAS). Node-only (child_process for
 * best-effort browser open) — this is exactly the kind of platform-specific
 * bit docs/OAUTH_SPEC.md Part B says stays out of `src/core/`; the actual
 * OIDC protocol calls all live in `src/core/oidc.ts` and are shared with the
 * UI's PKCE adapter.
 */
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import {
  discoverOidcIssuer,
  registerClient,
  startDeviceCodeLogin,
  waitForDeviceCodeLogin,
  isDeviceAccessTokenError,
  whoAmI,
} from "../core/oidc.js";
import { CliError } from "./errors.js";
import type { Session } from "./profile.js";
import { withOidcWindowShim } from "./oidcWindowPolyfill.js";

/** Generates a device ID the same shape matrix-js-sdk itself would (short
 * uppercase alphanumeric) — this CLI process chooses it upfront (unlike the
 * UI's authorization-code flow, where the SDK picks a random one) so it's
 * available immediately for logging/display and is guaranteed to match the
 * resulting Matrix device_id (embedded in the requested scope, see
 * `core/oidc.ts`'s `startDeviceCodeLogin`). */
function generateDeviceId(): string {
  return randomBytes(5).toString("hex").toUpperCase();
}

/** Best-effort: try to open the verification URL in the user's default
 * browser. Never throws — if it fails (headless box, no display, unknown
 * platform), the caller already printed the URL for the user to open by
 * hand. */
function tryOpenBrowser(url: string): void {
  const platform = process.platform;
  const cmd = platform === "darwin" ? "open" : platform === "win32" ? "start" : "xdg-open";
  try {
    const child = spawn(cmd, platform === "win32" ? ["", url] : [url], {
      detached: true,
      stdio: "ignore",
      shell: platform === "win32",
    });
    child.unref();
  } catch {
    // best-effort only
  }
}

export interface DeviceCodeLoginHooks {
  /** Called once the device+user code is known, before polling begins —
   * the caller (CLI command) prints it and attempts to open the browser. */
  onVerification: (info: { verificationUri: string; verificationUriComplete?: string; userCode: string }) => void;
}

/**
 * Runs the full device-code login flow against `homeserver`: discovery, DCR,
 * start device authorization, print verification info + try to open the
 * browser, poll until approved, confirm identity via `/whoami`. Returns a
 * `Session` ready to `writeSession()` — includes the OIDC token set fields
 * (`refreshToken`, `oidcIssuer`, `oidcClientId`, `oidcIdToken`) so later CLI
 * invocations can reuse + refresh it.
 */
export async function runDeviceCodeLogin(homeserver: string, hooks: DeviceCodeLoginHooks): Promise<Session> {
  // See src/cli/oidcWindowPolyfill.ts: discovery is the one OIDC call that
  // needs a `window` stub under Node, and the only place in the CLI it's
  // safe to install one — nothing crypto/WASM-related exists yet in this
  // process.
  const authMetadata = await withOidcWindowShim(() => discoverOidcIssuer(homeserver));
  if (!authMetadata.device_authorization_endpoint) {
    throw new CliError(
      `${homeserver} does not advertise OIDC device-code support (no device_authorization_endpoint) — try password login instead.`,
    );
  }

  const clientId = await registerClient(authMetadata, {
    clientName: "TeleCrypt.io CLI",
    clientUri: "https://telecrypt.io/",
    applicationType: "native",
    // Device-code flow never redirects a browser back to us, so this URI is
    // never actually dereferenced — it's a DCR-schema placeholder only.
    // Unverified against production MAS's DCR policy (only exercised here
    // against the local dev/test MAS, which allows insecure/mismatched
    // URIs); see docs/DECISIONS.md D6.
    redirectUris: ["http://localhost:0/"],
    contacts: undefined,
    tosUri: undefined,
    policyUri: undefined,
  });

  const deviceId = generateDeviceId();
  const session = await startDeviceCodeLogin(authMetadata, clientId, deviceId);

  hooks.onVerification({
    verificationUri: session.verification_uri,
    verificationUriComplete: session.verification_uri_complete,
    userCode: session.user_code,
  });
  tryOpenBrowser(session.verification_uri_complete ?? session.verification_uri);

  const result = await waitForDeviceCodeLogin(authMetadata, clientId, session);
  if (isDeviceAccessTokenError(result)) {
    throw new CliError(`device login was not approved: ${result.error_description ?? result.error}`);
  }

  const who = await whoAmI(homeserver, result.access_token);
  if (who.deviceId && who.deviceId !== deviceId) {
    throw new CliError(
      `device_id mismatch after OIDC login: requested ${deviceId}, server confirmed ${who.deviceId}`,
    );
  }

  return {
    homeserver,
    userId: who.userId,
    deviceId,
    accessToken: result.access_token,
    refreshToken: result.refresh_token,
    oidcIssuer: authMetadata.issuer,
    oidcClientId: clientId,
    oidcTokenEndpoint: authMetadata.token_endpoint,
  };
}
