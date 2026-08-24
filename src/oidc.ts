/**
 * CLI-only OIDC/MAS adapter: device-code login (RFC 8628) against a
 * homeserver's delegated auth service (MAS). Node-only (child_process for
 * best-effort browser open). The OIDC protocol calls live in the shared
 * `@telecrypt-io/storage/core` package.
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
  StorageError,
} from "@telecrypt-io/storage/core";
import type { OidcClientConfig } from "@telecrypt-io/storage/core";
import {
  canonicalMatrixServerName,
  expectedMatrixServerName,
  isCanonicalMatrixUserId,
  type PendingSession,
  type Session,
} from "./profile.js";
import { settlePromiseWithin } from "./cancellation.js";

/** Carries the exact bearer credentials that must be revoked when a device
 * grant succeeded but the CLI could not finish identity verification or
 * persistence. The message remains safe for user-facing output. */
export class OidcLoginError extends StorageError {
  readonly pendingSession: PendingSession;

  constructor(message: string, pendingSession: PendingSession) {
    super(message);
    this.name = "OidcLoginError";
    this.pendingSession = pendingSession;
  }
}

const MAX_OIDC_URL_LENGTH = 2048;
const MAX_USER_CODE_LENGTH = 256;
const OIDC_REQUEST_TIMEOUT_MS = 30_000;
const OIDC_APPROVAL_TIMEOUT_MS = 5 * 60_000;
const SAFE_DEVICE_ERROR_CODES = new Set([
  "access_denied",
  "authorization_pending",
  "expired",
  "expired_token",
  "invalid_client",
  "invalid_grant",
  "invalid_request",
  "invalid_scope",
  "invalid_token",
  "server_error",
  "slow_down",
  "temporarily_unavailable",
  "unauthorized_client",
  "unsupported_grant_type",
]);
const MAX_OIDC_VALUE_BYTES = 16 * 1024;

// The Matrix OIDC discovery client touches browser storage even in Node. Keep
// this shim scoped to discovery: a permanent global window breaks the SDK's
// Node crypto/runtime feature detection. The SDK 0.5/Matrix 42.2 release gate
// retains this compatibility boundary until the published SDK no longer
// needs it. The abort listener removes it even if discovery's body reader
// ignores cancellation and outlives the outer deadline.
class OidcMemoryStorage implements Storage {
  private readonly values = new Map<string, string>();

  get length(): number {
    return this.values.size;
  }

  clear(): void {
    this.values.clear();
  }

  getItem(key: string): string | null {
    return this.values.get(String(key)) ?? null;
  }

  key(index: number): string | null {
    return [...this.values.keys()][index] ?? null;
  }

  removeItem(key: string): void {
    this.values.delete(String(key));
  }

  setItem(key: string, value: string): void {
    this.values.set(String(key), String(value));
  }
}

interface OidcWindowShimOwner {
  value: unknown;
  owners: number;
}

// Discovery can run concurrently (for example, two test or orchestration
// invocations sharing one process). Keep the temporary shim alive until the
// last owner releases it; a simple hadWindow check lets the first completion
// delete a shim still in use by another invocation.
let activeOidcWindowShim: OidcWindowShimOwner | undefined;

async function withOidcWindowStorage<T>(
  operation: () => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  const globalObject = globalThis as unknown as Record<string, unknown>;
  const hadWindow = Object.prototype.hasOwnProperty.call(globalObject, "window");
  let owner: OidcWindowShimOwner | undefined;
  let restored = false;
  const restore = (): void => {
    if (restored) return;
    restored = true;
    signal?.removeEventListener("abort", restore);
    if (!owner) return;
    owner.owners -= 1;
    if (owner.owners > 0) return;
    if (activeOidcWindowShim === owner) activeOidcWindowShim = undefined;
    // A non-cooperative discovery call may still be running after the outer
    // deadline returns. Remove only the shim this invocation owns; do not
    // overwrite a replacement installed by another owner.
    if (globalObject.window === owner.value) delete globalObject.window;
  };
  if (activeOidcWindowShim && globalObject.window === activeOidcWindowShim.value) {
    owner = activeOidcWindowShim;
    owner.owners += 1;
  } else if (!hadWindow) {
    owner = {
      value: {
        sessionStorage: new OidcMemoryStorage(),
        localStorage: new OidcMemoryStorage(),
      },
      owners: 1,
    };
    activeOidcWindowShim = owner;
    globalObject.window = owner.value;
  }
  signal?.addEventListener("abort", restore, { once: true });
  try {
    return await operation();
  } finally {
    // An existing non-shim window belongs to its caller. Joined shim owners
    // release only their reference, and no branch overwrites a replacement
    // made by another invocation (or by the operation itself).
    restore();
  }
}

function isExactLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}

function requireOpaqueValue(value: unknown, name: string): string {
  if (
    typeof value !== "string" ||
    value.trim() === "" ||
    Buffer.byteLength(value, "utf8") > MAX_OIDC_VALUE_BYTES ||
    /[\s\u0000-\u001f\u007f-\u009f]/u.test(value)
  ) {
    throw new StorageError(`${name} is invalid`);
  }
  return value;
}

function requireUserId(value: unknown): string {
  const userId = requireOpaqueValue(value, "OIDC user ID");
  if (!isCanonicalMatrixUserId(userId)) throw new StorageError("OIDC identity verification failed");
  return userId;
}

function safeDeviceAccessError(error: unknown): string {
  if (typeof error === "string" && SAFE_DEVICE_ERROR_CODES.has(error)) {
    return `device login was not approved (${error})`;
  }
  return "device login was not approved";
}

/** Adds a real abort boundary around SDK OIDC calls. The SDK 0.5 OIDC
 * operations receive this signal directly; cooperative calls abort their HTTP
 * request and polling delay, while a broken call is reaped only for a bounded
 * grace period before this function fails closed. */
async function withDeadline<T>(
  operation: (signal: AbortSignal) => Promise<T>,
  label: string,
  timeoutMs: number,
  externalSignal?: AbortSignal,
  cancelledSuccess?: (value: T, boundaryError: StorageError) => Error,
): Promise<T> {
  if (externalSignal?.aborted) throw new StorageError("OIDC operation cancelled");
  const controller = new AbortController();
  const timeoutError = new StorageError(`${label} timed out`);
  let boundaryError: StorageError | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onExternalAbort: (() => void) | undefined;
  const operationPromise = Promise.resolve().then(() => {
    if (controller.signal.aborted || externalSignal?.aborted) {
      throw boundaryError ?? new StorageError("OIDC operation cancelled");
    }
    return operation(controller.signal);
  });
  // A signal-aware callee should stop promptly, but keep its eventual
  // rejection handled when a broken/older callee ignores the signal and the
  // hard deadline wins the race.
  operationPromise.catch(() => undefined);
  const cancellation = new Promise<never>((_, reject) => {
    const handler = () => {
      boundaryError = new StorageError("OIDC operation cancelled");
      controller.abort(externalSignal?.reason);
      reject(boundaryError);
    };
    onExternalAbort = handler;
    if (externalSignal?.aborted) handler();
    else externalSignal?.addEventListener("abort", handler, { once: true });
  });
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      boundaryError = timeoutError;
      controller.abort(timeoutError);
      reject(timeoutError);
    }, timeoutMs);
  });
  try {
    const result = await Promise.race([operationPromise, cancellation, deadline]);
    if (externalSignal?.aborted) throw new StorageError("OIDC operation cancelled");
    if (controller.signal.aborted) throw timeoutError;
    return result;
  } catch (error) {
    if (controller.signal.aborted) {
      const settlement = await settlePromiseWithin(operationPromise);
      const finalBoundary = externalSignal?.aborted
        ? new StorageError("OIDC operation cancelled")
        : boundaryError ?? timeoutError;
      if (settlement.status === "fulfilled" && cancelledSuccess) {
        throw cancelledSuccess(settlement.value, finalBoundary);
      }
      throw finalBoundary;
    }
    throw error;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (onExternalAbort) externalSignal?.removeEventListener("abort", onExternalAbort);
  }
}

function parseOidcUrl(value: unknown, name: string, allowQuery = false, canonical = true): URL {
  if (typeof value !== "string" || value.trim() === "") {
    throw new StorageError(`${name} must be a non-empty URL`);
  }
  if (value.length > MAX_OIDC_URL_LENGTH) {
    throw new StorageError(`${name} exceeds maximum length`);
  }
  if (/[\u0000-\u001f\u007f-\u009f]/u.test(value)) {
    throw new StorageError(`${name} contains invalid control characters`);
  }

  if (value !== value.trim()) {
    throw new StorageError(`${name} must not have surrounding whitespace`);
  }

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new StorageError(`${name} must be a valid URL`);
  }

  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    (!allowQuery && parsed.search !== "") ||
    parsed.hash !== "" ||
    (canonical &&
      parsed.toString() !== value &&
      !(parsed.pathname === "/" && parsed.toString() === `${value}/`))
  ) {
    throw new StorageError(`${name} must be a canonical HTTP(S) URL without credentials, queries, or fragments`);
  }
  if (parsed.protocol === "http:" && !isExactLoopbackHost(parsed.hostname)) {
    throw new StorageError(`${name} must use HTTPS except for the exact loopback host`);
  }
  return parsed;
}

/** Validates the user-supplied homeserver before any discovery request. */
export function assertTrustedHomeserver(value: unknown): string {
  parseOidcUrl(value, "homeserver", false, false);
  return value as string;
}

function isWithinIssuerPath(issuer: URL, endpoint: URL): boolean {
  if (issuer.pathname === "/") return true;
  const prefix = issuer.pathname.endsWith("/") ? issuer.pathname : `${issuer.pathname}/`;
  return endpoint.pathname === issuer.pathname || endpoint.pathname.startsWith(prefix);
}

/** Validates an OIDC endpoint before registration, authorization, or refresh tokens are sent. */
export function assertOidcEndpoint(
  value: unknown,
  trustedHomeserver: string,
  name: string,
  issuer?: URL,
  allowQuery = false,
): string {
  const homeserver = parseOidcUrl(trustedHomeserver, "homeserver", false, false);
  const endpoint = parseOidcUrl(value, name, allowQuery);
  if (endpoint.origin !== homeserver.origin || (issuer && !isWithinIssuerPath(issuer, endpoint))) {
    throw new StorageError(`${name} must remain on the configured OIDC origin and issuer path`);
  }
  return endpoint.toString();
}

function assertSafeVerificationUri(
  value: unknown,
  trustedHomeserver: string,
  name: string,
  issuer: URL,
): string {
  const endpoint = new URL(assertOidcEndpoint(value, trustedHomeserver, name, issuer, true));
  for (const [key, queryValue] of endpoint.searchParams) {
    // The device-code page may carry a user code, but it must not turn the
    // CLI's trusted browser launch into an open redirect or nested URL.
    if (/(?:^|_)(?:redirect|return|next|continue)(?:$|_)/iu.test(key) || /^(?:https?:)?\/\//iu.test(queryValue)) {
      throw new StorageError(`${name} contains an unsafe redirect parameter`);
    }
  }
  return endpoint.toString();
}

/** Validates every OIDC URL the CLI will use before dynamic registration. */
export function validateOidcMetadata(metadata: OidcClientConfig, homeserver: string): OidcClientConfig {
  const trustedHomeserver = parseOidcUrl(homeserver, "homeserver", false, false);
  const issuer = parseOidcUrl(metadata.issuer, "OIDC issuer");
  if (issuer.origin !== trustedHomeserver.origin) {
    throw new StorageError("OIDC issuer must remain on the configured homeserver origin");
  }

  const endpoints: Array<[string, unknown]> = [
    ["OIDC authorization endpoint", metadata.authorization_endpoint],
    ["OIDC device authorization endpoint", metadata.device_authorization_endpoint],
    ["OIDC registration endpoint", metadata.registration_endpoint],
    ["OIDC token endpoint", metadata.token_endpoint],
  ];
  if (metadata.revocation_endpoint !== undefined) {
    endpoints.push(["OIDC revocation endpoint", metadata.revocation_endpoint]);
  }
  for (const [name, endpoint] of endpoints) {
    assertOidcEndpoint(endpoint, homeserver, name, issuer);
  }
  if (metadata.jwks_uri !== undefined) {
    assertOidcEndpoint(metadata.jwks_uri, homeserver, "OIDC JWKS endpoint", issuer);
  }
  return metadata;
}

/** Generates a device ID the same shape matrix-js-sdk itself would (short
 * uppercase alphanumeric) — this CLI process chooses it upfront (unlike the
 * UI's authorization-code flow, where the SDK picks a random one) so it's
 * available immediately for logging/display and is guaranteed to match the
 * resulting Matrix device_id (embedded in the requested scope, see the
 * shared storage core's `startDeviceCodeLogin`). */
function generateDeviceId(): string {
  return randomBytes(5).toString("hex").toUpperCase();
}

/** Best-effort: try to open the verification URL in the user's default
 * browser. Never throws — if it fails (headless box, no display, unknown
 * platform), the caller already printed the URL for the user to open by
 * hand. */
export function tryOpenBrowser(url: string): void {
  const platform = process.platform;
  // Windows' `start` is a cmd.exe builtin and would require a shell. Avoid
  // passing an issuer-provided URL through a command interpreter; the URL is
  // already printed for the user to open manually.
  if (platform === "win32") return;
  const cmd = platform === "darwin" ? "open" : "xdg-open";
  try {
    const child = spawn(cmd, [url], {
      detached: true,
      stdio: "ignore",
    });
    // Detached launchers can report an asynchronous ENOENT/EACCES after
    // spawn() returns. This browser open is optional; consume that error so
    // it cannot become an uncaught process error.
    child.once("error", () => {});
    child.unref();
  } catch {
    // best-effort only
  }
}

export interface DeviceCodeLoginHooks {
  /** Called once the device+user code is known, before polling begins —
   * the caller (CLI command) prints it and attempts to open the browser. */
  onVerification: (info: { verificationUri: string; verificationUriComplete?: string; userCode: string }) => void;
  /** Suppresses the optional best-effort browser launch for headless users. */
  openBrowser?: boolean;
}

/**
 * Runs the full device-code login flow against `homeserver`: discovery, DCR,
 * start device authorization, print verification info + try to open the
 * browser, poll until approved, confirm identity via `/whoami`. Returns a
 * `Session` ready to `writeSession()` with the token endpoint needed for
 * later refreshes.
 */
export async function runDeviceCodeLogin(
  homeserver: string,
  hooks: DeviceCodeLoginHooks,
  signal?: AbortSignal,
): Promise<Session> {
  const trustedHomeserver = assertTrustedHomeserver(homeserver);
  const trustedMatrixServerName = expectedMatrixServerName(trustedHomeserver);
  if (!trustedMatrixServerName) {
    throw new StorageError("homeserver is not a supported TeleCrypt deployment");
  }
  const discoveredMetadata = await withDeadline(
    (requestSignal) => withOidcWindowStorage(
      () => discoverOidcIssuer(trustedHomeserver, requestSignal),
      requestSignal,
    ),
    "OIDC discovery",
    OIDC_REQUEST_TIMEOUT_MS,
    signal,
  );
  const authMetadata = validateOidcMetadata(discoveredMetadata, trustedHomeserver);
  const issuer = parseOidcUrl(authMetadata.issuer, "OIDC issuer");
  const oidcIssuer = issuer.toString();
  const oidcTokenEndpoint = assertOidcEndpoint(
    authMetadata.token_endpoint,
    trustedHomeserver,
    "OIDC token endpoint",
    issuer,
  );
  const oidcRevocationEndpoint = authMetadata.revocation_endpoint === undefined
    ? undefined
    : assertOidcEndpoint(
        authMetadata.revocation_endpoint,
        trustedHomeserver,
        "OIDC revocation endpoint",
        issuer,
      );

  const clientId = requireOpaqueValue(await withDeadline(
    (requestSignal) => registerClient(authMetadata, {
      clientName: "TeleCrypt.io CLI",
      clientUri: "https://telecrypt.io/",
      applicationType: "native",
      // Device-code flow never redirects a browser back to us, so this URI is
      // never dereferenced. Keep the required DCR value on the same trusted
      // origin as clientUri so production issuers need no mismatch exception.
      redirectUris: ["https://telecrypt.io/"],
      contacts: undefined,
      tosUri: undefined,
      policyUri: undefined,
    }, requestSignal),
    "OIDC client registration",
    OIDC_REQUEST_TIMEOUT_MS,
    signal,
  ), "OIDC client ID");

  const deviceId = generateDeviceId();
  const session = await withDeadline(
    (requestSignal) => startDeviceCodeLogin(authMetadata, clientId, deviceId, requestSignal),
    "OIDC device authorization",
    OIDC_REQUEST_TIMEOUT_MS,
    signal,
  );
  if (signal?.aborted) throw new StorageError("OIDC operation cancelled");
  const verificationUri = assertSafeVerificationUri(
    session.verification_uri,
    trustedHomeserver,
    "OIDC verification URI",
    issuer,
  );
  const verificationUriComplete = session.verification_uri_complete !== undefined
    ? assertSafeVerificationUri(
        session.verification_uri_complete,
        trustedHomeserver,
        "OIDC complete verification URI",
        issuer,
      )
    : undefined;
  if (typeof session.user_code !== "string" || session.user_code.trim() === "") {
    throw new StorageError("OIDC user code must be a non-empty string");
  }
  if (session.user_code.length > MAX_USER_CODE_LENGTH) {
    throw new StorageError("OIDC user code exceeds maximum length");
  }
  if (session.user_code !== session.user_code.trim()) {
    throw new StorageError("OIDC user code must not have surrounding whitespace");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(session.user_code)) {
    throw new StorageError("OIDC user code contains unsupported characters");
  }

  hooks.onVerification({
    verificationUri,
    verificationUriComplete,
    userCode: session.user_code,
  });
  if (hooks.openBrowser !== false) {
    tryOpenBrowser(verificationUriComplete ?? verificationUri);
  }

  const result = await withDeadline(
    (requestSignal) => waitForDeviceCodeLogin(authMetadata, clientId, session, requestSignal),
    "OIDC approval",
    OIDC_APPROVAL_TIMEOUT_MS,
    signal,
    (lateResult, boundaryError) => {
      if (isDeviceAccessTokenError(lateResult)) return boundaryError;
      let accessToken: string;
      try {
        accessToken = requireOpaqueValue(lateResult.access_token, "OIDC access token");
      } catch {
        return boundaryError;
      }
      const pending: PendingSession = {
        homeserver: trustedHomeserver,
        deviceId,
        accessToken,
        oidcIssuer,
        oidcClientId: clientId,
        oidcTokenEndpoint,
        oidcRevocationEndpoint,
        matrixServerName: trustedMatrixServerName,
      };
      if (lateResult.refresh_token) {
        try {
          pending.refreshToken = requireOpaqueValue(lateResult.refresh_token, "OIDC refresh token");
        } catch {
          // The access token remains revocable even when the refresh field is malformed.
        }
      }
      return new OidcLoginError(boundaryError.message, pending);
    },
  );
  if (isDeviceAccessTokenError(result)) {
    throw new StorageError(safeDeviceAccessError(result.error));
  }
  const accessToken = requireOpaqueValue(result.access_token, "OIDC access token");
  const pending: PendingSession = {
    homeserver: trustedHomeserver,
    deviceId,
    accessToken,
    oidcIssuer,
    oidcClientId: clientId,
    oidcTokenEndpoint,
    oidcRevocationEndpoint,
    matrixServerName: trustedMatrixServerName,
  };
  if (!result.refresh_token) {
    throw new OidcLoginError("device login returned no refresh token", pending);
  }
  let refreshToken: string;
  try {
    refreshToken = requireOpaqueValue(result.refresh_token, "OIDC refresh token");
  } catch (error) {
    throw new OidcLoginError(error instanceof Error ? error.message : "OIDC refresh token is invalid", pending);
  }
  pending.refreshToken = refreshToken;

  // Once the token endpoint has issued a bearer token, every later failure
  // must retain the exact credentials for the login transaction's cleanup
  // path.  Do not discard a successful poll merely because cancellation was
  // observed at this boundary.
  if (signal?.aborted) throw new OidcLoginError("OIDC operation cancelled", pending);

  try {
    const who = await withDeadline(
      (requestSignal) => whoAmI(trustedHomeserver, accessToken, requestSignal),
      "OIDC identity verification",
      OIDC_REQUEST_TIMEOUT_MS,
      signal,
    );
    const userId = requireUserId(who.userId);
    const matrixServerName = canonicalMatrixServerName(userId);
    if (!matrixServerName || matrixServerName !== trustedMatrixServerName) {
      throw new StorageError("OIDC identity does not match the configured TeleCrypt deployment");
    }
    pending.userId = userId;
    pending.matrixServerName = matrixServerName;
    if (typeof who.deviceId !== "string" || who.deviceId !== deviceId) {
      throw new StorageError("OIDC identity verification failed");
    }
    requireOpaqueValue(who.deviceId, "OIDC device ID");

    return {
      homeserver: trustedHomeserver,
      userId,
      matrixServerName,
      deviceId,
      accessToken,
      refreshToken,
      oidcIssuer,
      oidcClientId: clientId,
      oidcTokenEndpoint,
      oidcRevocationEndpoint,
    };
  } catch (error) {
    if (error instanceof OidcLoginError) throw error;
    const message = error instanceof Error ? error.message : "OIDC identity verification failed";
    throw new OidcLoginError(message, pending);
  }
}
