/**
 * CLI-only OIDC/MAS adapter: device-code login (RFC 8628) against a
 * homeserver's delegated auth service (MAS). Node-only (child_process for
 * best-effort browser open). The OIDC protocol calls live in the shared
 * `@telecrypt-io/storage/core` package.
 */
import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import {
  assertOidcEndpoint,
  discoverOidcIssuer,
  registerClient,
  startDeviceCodeLogin,
  waitForDeviceCodeLogin,
  isDeviceAccessTokenError,
  whoAmI,
  StorageError,
} from "@telecrypt-io/storage/core";
export { assertOidcEndpoint };
import type { PendingSession, Session } from "./profile.js";
import { settlePromiseWithin } from "./cancellation.js";
import { expectedMatrixServerName } from "./topology.js";

/** Carries the exact bearer credentials that must be revoked when a device
 * grant succeeded but the CLI could not finish identity verification or
 * persistence. The message remains safe for user-facing output. */
export class OidcLoginError extends StorageError {
  readonly pendingSession: PendingSession;

  constructor(message: string, pendingSession: PendingSession, options?: ErrorOptions) {
    super(message, options);
    this.name = "OidcLoginError";
    this.pendingSession = pendingSession;
  }
}

const OIDC_REQUEST_TIMEOUT_MS = 30_000;
const OIDC_APPROVAL_TIMEOUT_MS = 5 * 60_000;
function deviceAccessError(error: unknown): string {
  return typeof error === "string" && error
    ? `device login was not approved (${error})`
    : "device login was not approved";
}

/** Adds a real abort boundary around SDK OIDC calls. The SDK OIDC operations
 * receive this signal directly; cooperative calls abort their HTTP request and
 * polling delay. Approval joins a late token result so its credentials remain
 * available for mandatory revocation. */
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
      const finalBoundary = externalSignal?.aborted
        ? new StorageError("OIDC operation cancelled")
        : boundaryError ?? timeoutError;
      const settlement = await settlePromiseWithin(operationPromise);
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

/** Validates the user-supplied homeserver against the supported TeleCrypt deployments. */
export function assertTrustedHomeserver(value: unknown): string {
  if (typeof value !== "string" || !expectedMatrixServerName(value)) {
    throw new StorageError("homeserver is not a supported TeleCrypt deployment");
  }
  return value;
}

function assertSafeVerificationUri(
  value: unknown,
  trustedHomeserver: string,
  name: string,
  issuer: URL,
): string {
  return assertOidcEndpoint(value, trustedHomeserver, name, issuer, true);
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
  const trustedMatrixServerName = expectedMatrixServerName(trustedHomeserver)!;
  const discoveredMetadata = await withDeadline(
    (requestSignal) => discoverOidcIssuer(trustedHomeserver, requestSignal),
    "OIDC discovery",
    OIDC_REQUEST_TIMEOUT_MS,
    signal,
  );
  const issuer = new URL(assertOidcEndpoint(discoveredMetadata.issuer, trustedHomeserver, "OIDC issuer"));
  const oidcIssuer = issuer.toString();
  const oidcTokenEndpoint = assertOidcEndpoint(
    discoveredMetadata.token_endpoint,
    trustedHomeserver,
    "OIDC token endpoint",
    issuer,
  );
  const oidcRevocationEndpoint = discoveredMetadata.revocation_endpoint === undefined
    ? undefined
    : assertOidcEndpoint(
        discoveredMetadata.revocation_endpoint,
        trustedHomeserver,
        "OIDC revocation endpoint",
        issuer,
      );

  const clientId = await withDeadline(
    (requestSignal) => registerClient(discoveredMetadata, {
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
  );

  const deviceId = generateDeviceId();
  const session = await withDeadline(
    (requestSignal) => startDeviceCodeLogin(discoveredMetadata, clientId, deviceId, requestSignal),
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
  hooks.onVerification({
    verificationUri,
    verificationUriComplete,
    userCode: session.user_code,
  });
  if (hooks.openBrowser !== false) {
    tryOpenBrowser(verificationUriComplete ?? verificationUri);
  }

  const result = await withDeadline(
    (requestSignal) => waitForDeviceCodeLogin(discoveredMetadata, clientId, session, requestSignal),
    "OIDC approval",
    OIDC_APPROVAL_TIMEOUT_MS,
    signal,
    (lateResult, boundaryError) => {
      if (isDeviceAccessTokenError(lateResult)) return boundaryError;
      const lateAccessToken = lateResult.access_token;
      const pending: PendingSession = {
        homeserver: trustedHomeserver,
        deviceId,
        accessToken: lateAccessToken,
        oidcIssuer,
        oidcClientId: clientId,
        oidcTokenEndpoint,
        oidcRevocationEndpoint,
        matrixServerName: trustedMatrixServerName,
      };
      if (lateResult.refresh_token) pending.refreshToken = lateResult.refresh_token;
      return new OidcLoginError(boundaryError.message, pending);
    },
  );
  if (isDeviceAccessTokenError(result)) {
    throw new StorageError(deviceAccessError(result.error));
  }
  const accessToken = result.access_token;
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
  const refreshToken = result.refresh_token;
  pending.refreshToken = refreshToken;

  // Once the token endpoint has issued a bearer token, every later failure
  // must retain the exact credentials for the login transaction's cleanup
  // path.  Do not discard a successful poll merely because cancellation was
  // observed at this boundary.
  if (signal?.aborted) throw new OidcLoginError("OIDC operation cancelled", pending);

  try {
    const who = await withDeadline(
      (requestSignal) => whoAmI(trustedHomeserver, accessToken, trustedMatrixServerName, requestSignal),
      "OIDC identity verification",
      OIDC_REQUEST_TIMEOUT_MS,
      signal,
    );
    const userId = who.userId;
    const matrixServerName = trustedMatrixServerName;
    pending.userId = userId;
    pending.matrixServerName = matrixServerName;
    if (who.deviceId !== deviceId) {
      throw new StorageError("OIDC identity verification failed");
    }

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
    throw new OidcLoginError(message, pending, { cause: error });
  }
}
