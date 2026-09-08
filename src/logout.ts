import { StorageError } from "@telecrypt-io/storage/core";
import {
  acquireProfileLock,
  clearProfileUnlocked,
  hasLogoutMarker,
  readPendingSession,
  readSession,
  profileDir,
  throwWithLockReleaseFailure,
  writeLogoutMarkerUnlocked,
  writePendingSessionUnlocked,
  writeSessionUnlocked,
  isBoundedOpaqueValue,
} from "./profile.js";
import type { ProfileLock } from "./profile.js";
import { assertOidcEndpoint, assertTrustedHomeserver } from "./oidc.js";
import {
  commandSignal,
  readReadableStreamChunkWithAbort,
  settlePromiseWithin,
} from "./cancellation.js";
import { throwCombinedFailures, withCause } from "./failure.js";
import { safeDiagnosticText } from "./output.js";

const DEFAULT_LOGOUT_TIMEOUT_MS = 10_000;
const MAX_LOGOUT_TIMEOUT_MS = 120_000;

async function cancelLogoutReader(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<void> {
  const cancellation = Promise.resolve().then(() => reader.cancel());
  const settlement = await settlePromiseWithin(cancellation);
  if (settlement.status === "rejected") throw settlement.error;
  if (settlement.status === "timeout") {
    throw new StorageError("server logout response cleanup timed out");
  }
}

async function cleanupLogoutReader(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  cancel: boolean,
): Promise<unknown[]> {
  const failures: unknown[] = [];
  if (cancel) {
    try {
      await cancelLogoutReader(reader);
    } catch (error) {
      failures.push(error);
    }
  }
  try {
    reader.releaseLock();
  } catch (error) {
    failures.push(error);
  }
  return failures;
}

async function cleanupLogoutResponseBody(response: Response): Promise<unknown[]> {
  if (!response.body) return [];
  let reader: ReadableStreamDefaultReader<Uint8Array>;
  try {
    reader = response.body.getReader();
  } catch (error) {
    return [error];
  }
  return cleanupLogoutReader(reader, true);
}

async function consumeLogoutResponse(
  response: Response,
  readSignal: AbortSignal,
): Promise<{ value: unknown; text: string } | undefined> {
  if (!response.body) return undefined;
  const reader = response.body.getReader();
  const cancellationError = new StorageError("server logout response read cancelled");
  const chunks: Uint8Array[] = [];
  let primaryError: unknown;
  let hasPrimary = false;
  try {
    while (true) {
      const chunk = await readReadableStreamChunkWithAbort(reader, readSignal, cancellationError);
      if (chunk.done) break;
      chunks.push(chunk.value);
    }
  } catch (error) {
    hasPrimary = true;
    primaryError = error;
  }
  const partialText = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
  if (hasPrimary) {
    const bodyDiagnostic = new Error(`server logout response body: ${safeDiagnosticText(partialText)}`);
    primaryError = withCause(
      new StorageError("server logout response body could not be read"),
      new AggregateError(
        [primaryError, bodyDiagnostic],
        "server logout response read failed with a partial body",
        { cause: primaryError },
      ),
    );
  }
  // readReadableStreamChunkWithAbort owns cancellation after a read failure;
  // this boundary only releases the reader so a cancellation failure is not
  // attempted (and reported) twice.
  const cleanupFailures = await cleanupLogoutReader(reader, false);
  if (!hasPrimary && cleanupFailures.length > 0 && chunks.length > 0) {
    throw new AggregateError(
      [...cleanupFailures, new Error(`server logout response body: ${safeDiagnosticText(partialText)}`)],
      "server logout response cleanup failed",
    );
  }
  if (hasPrimary || cleanupFailures.length > 0) {
    throwCombinedFailures(primaryError, hasPrimary, cleanupFailures, "server logout response cleanup failed");
  }
  if (chunks.length === 0) return undefined;
  const text = partialText;
  try {
    return { value: JSON.parse(text) as unknown, text };
  } catch (error) {
    throw withCause(
      new StorageError("server logout response is not valid JSON"),
      new AggregateError(
        [error, new Error(`server logout response body: ${safeDiagnosticText(text)}`)],
        "server logout response JSON parse failed",
        { cause: error },
      ),
    );
  }
}

function isUnknownAccessTokenResponse(status: number, body: unknown): boolean {
  return (
    status === 401 &&
    Boolean(body) &&
    typeof body === "object" &&
    (body as { errcode?: unknown }).errcode === "M_UNKNOWN_TOKEN"
  );
}

function localLogoutCleanupError(cause: unknown): StorageError {
  return withCause(
    new StorageError("server logout succeeded but local cleanup is incomplete — retry logout"),
    cause,
  );
}

function safeLogoutRequestFailure(error: unknown): StorageError {
  const primary = error instanceof AggregateError ? error.errors[0] : undefined;
  const message = primary instanceof StorageError ? primary.message : "server logout request failed";
  return withCause(new StorageError(message), error);
}

interface LogoutCredentials {
  homeserver: string;
  accessToken: string;
  oidcIssuer: string;
  refreshToken?: string;
  oidcClientId?: string;
  oidcTokenEndpoint?: string;
  oidcRevocationEndpoint?: string;
}

type RefreshedLogoutCredentials = LogoutCredentials & {
  refreshToken: string;
  oidcClientId: string;
  oidcTokenEndpoint: string;
};

function refreshedCredentials(
  session: LogoutCredentials,
  body: unknown,
): RefreshedLogoutCredentials {
  if (!body || typeof body !== "object") throw new StorageError("OIDC refresh response is invalid");
  const response = body as { access_token?: unknown; refresh_token?: unknown };
  if (!isBoundedOpaqueValue(response.access_token)) {
    throw new StorageError("OIDC refresh response contained an invalid access token");
  }
  const nextRefresh = response.refresh_token ?? session.refreshToken;
  if (!isBoundedOpaqueValue(nextRefresh)) {
    throw new StorageError("OIDC refresh response contained an invalid refresh token");
  }
  if (!isBoundedOpaqueValue(session.oidcClientId) || typeof session.oidcTokenEndpoint !== "string") {
    throw new StorageError("persisted OIDC refresh state is incomplete");
  }
  return {
    ...session,
    accessToken: response.access_token,
    oidcIssuer: session.oidcIssuer,
    refreshToken: nextRefresh,
    oidcClientId: session.oidcClientId,
    oidcTokenEndpoint: session.oidcTokenEndpoint,
    oidcRevocationEndpoint: session.oidcRevocationEndpoint,
  };
}

/** Revokes the server session without ever including the access token in an
 * error. Local state must remain until this request succeeds. */
export async function requestServerLogout(
  session: LogoutCredentials,
  timeoutMs = DEFAULT_LOGOUT_TIMEOUT_MS,
  externalSignal?: AbortSignal,
  onRefreshed?: (credentials: RefreshedLogoutCredentials) => void,
): Promise<void> {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new StorageError("server logout timeout must be positive");
  }
  if (timeoutMs > MAX_LOGOUT_TIMEOUT_MS) {
    throw new StorageError("server logout timeout exceeds the allowed maximum");
  }
  if (!isBoundedOpaqueValue(session.accessToken)) {
    throw new StorageError("server logout token is invalid");
  }

  const trustedHomeserver = assertTrustedHomeserver(session.homeserver);
  const issuer = new URL(assertOidcEndpoint(session.oidcIssuer, trustedHomeserver, "OIDC issuer"));
  if (session.oidcRevocationEndpoint !== undefined) {
    assertOidcEndpoint(
      session.oidcRevocationEndpoint,
      trustedHomeserver,
      "OIDC revocation endpoint",
      issuer,
    );
  }
  const base = new URL(trustedHomeserver);
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  const endpoint = assertOidcEndpoint(
    new URL("_matrix/client/v3/logout", base).toString(),
    trustedHomeserver,
    "logout endpoint",
  );
  const controller = new AbortController();
  let boundaryError: StorageError | undefined;
  let acceptRefreshedCredentials = true;
  let rejectBoundary!: (error: StorageError) => void;
  const boundary = new Promise<never>((_, reject) => {
    rejectBoundary = reject;
  });
  const onExternalAbort = () => {
    if (boundaryError) return;
    acceptRefreshedCredentials = false;
    boundaryError = new StorageError("server logout cancelled");
    controller.abort(externalSignal?.reason);
    rejectBoundary(boundaryError);
  };
  externalSignal?.addEventListener("abort", onExternalAbort, { once: true });
  if (externalSignal?.aborted) {
    externalSignal.removeEventListener("abort", onExternalAbort);
    throw new StorageError("server logout cancelled");
  }
  const timer = setTimeout(() => {
    if (boundaryError) return;
    acceptRefreshedCredentials = false;
    boundaryError = new StorageError("server logout request timed out");
    controller.abort(boundaryError);
    rejectBoundary(boundaryError);
  }, timeoutMs);
  const requestLogout = async (
    accessToken: string,
  ): Promise<{ status: number; body: unknown; bodyText?: string }> => {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}` },
      redirect: "manual",
      signal: controller.signal,
    });
    if (response.url !== endpoint) {
      const error = new StorageError("server logout redirected unexpectedly");
      controller.abort(error);
      const cleanupFailures = await cleanupLogoutResponseBody(response);
      throwCombinedFailures(error, true, cleanupFailures, "server logout response cleanup failed");
    }
    const consumed = await consumeLogoutResponse(response, controller.signal);
    return { status: response.status, body: consumed?.value, bodyText: consumed?.text };
  };
  const operation = (async () => {
    let credentials: LogoutCredentials = session;
    let logoutResponse = await requestLogout(credentials.accessToken);
    if (logoutResponse.status === 200 || logoutResponse.status === 204) return;
    if (!isUnknownAccessTokenResponse(logoutResponse.status, logoutResponse.body)) {
      const error = new StorageError(`server logout failed (HTTP ${logoutResponse.status})`);
      if (logoutResponse.bodyText !== undefined) {
        withCause(error, new Error(`server logout response body: ${safeDiagnosticText(logoutResponse.bodyText)}`));
      }
      throw error;
    }

    if (!credentials.refreshToken) return;
    if (!credentials.oidcClientId || !credentials.oidcTokenEndpoint) {
      throw new StorageError("access token is no longer valid but live refresh state is incomplete");
    }
    const tokenEndpoint = assertOidcEndpoint(
      credentials.oidcTokenEndpoint,
      trustedHomeserver,
      "OIDC token endpoint",
      issuer,
    );
    const refreshResponse = await fetch(tokenEndpoint, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: credentials.refreshToken,
        client_id: credentials.oidcClientId,
      }),
      redirect: "manual",
      signal: controller.signal,
    });
    if (refreshResponse.url !== tokenEndpoint) {
      const error = new StorageError("OIDC token refresh redirected unexpectedly");
      controller.abort(error);
      const cleanupFailures = await cleanupLogoutResponseBody(refreshResponse);
      throwCombinedFailures(error, true, cleanupFailures, "server logout response cleanup failed");
    }
    const consumedRefresh = await consumeLogoutResponse(refreshResponse, controller.signal);
    const refreshBody = consumedRefresh?.value;
    if (
      refreshResponse.status === 400 &&
      refreshBody &&
      typeof refreshBody === "object" &&
      (refreshBody as { error?: unknown }).error === "invalid_grant"
    ) {
      return;
    }
    if (refreshResponse.status !== 200) {
      const error = new StorageError(`OIDC token refresh failed (HTTP ${refreshResponse.status})`);
      if (consumedRefresh?.text !== undefined) {
        withCause(error, new Error(`OIDC token refresh response body: ${safeDiagnosticText(consumedRefresh.text)}`));
      }
      throw error;
    }
    credentials = refreshedCredentials(credentials, refreshBody);
    if (acceptRefreshedCredentials) {
      onRefreshed?.(credentials as RefreshedLogoutCredentials);
    }
    logoutResponse = await requestLogout(credentials.accessToken);
    if (logoutResponse.status !== 200 && logoutResponse.status !== 204) {
      const error = new StorageError(`server logout failed (HTTP ${logoutResponse.status})`);
      if (logoutResponse.bodyText !== undefined) {
        withCause(error, new Error(`server logout response body: ${safeDiagnosticText(logoutResponse.bodyText)}`));
      }
      throw error;
    }
  })();
  try {
    await Promise.race([operation, boundary]);
    if (boundaryError) throw boundaryError;
    if (externalSignal?.aborted) throw new StorageError("server logout cancelled");
  } catch (error) {
    if (boundaryError) {
      acceptRefreshedCredentials = false;
      throw boundaryError;
    }
    if (externalSignal?.aborted) {
      throw withCause(new StorageError("server logout cancelled"), error);
    }
    if (error instanceof StorageError) throw error;
    throw safeLogoutRequestFailure(error);
  } finally {
    clearTimeout(timer);
    acceptRefreshedCredentials = false;
    externalSignal?.removeEventListener("abort", onExternalAbort);
  }
}

export interface LogoutResult {
  hadSession: boolean;
  serverLogout: "revoked" | "not-needed";
}

/** Completes local cleanup after the server has confirmed revocation. The
 * marker makes a later retry idempotent if deletion is interrupted. If marker
 * persistence itself fails, direct cleanup is attempted before surfacing the
 * incomplete local state. */
export function finishRemoteLogout(dir: string = profileDir(), heldLock?: ProfileLock): void {
  try {
    writeLogoutMarkerUnlocked(dir, heldLock);
  } catch (markerError) {
    try {
      clearProfileUnlocked(dir, {}, heldLock);
      return;
    } catch (localCleanupError) {
      throw localLogoutCleanupError(new AggregateError(
        [markerError, localCleanupError],
        "server logout local cleanup failed",
      ));
    }
  }
  try {
    // Keep the marker in place while checking the rest of the profile. If an
    // unexpected entry makes cleanup incomplete, a retry can still prove that
    // the remote session was already revoked without using the old token.
    clearProfileUnlocked(dir, { preserveLogoutMarker: true }, heldLock);
  } catch (localCleanupError) {
    throw localLogoutCleanupError(localCleanupError);
  }
}

/**
 * Revokes the remote session before deleting local credentials. If revocation
 * fails, the profile remains intact so the caller can retry when connectivity
 * returns. Local state is only removed after the server confirms success.
 */
export async function logoutProfile(
  dir: string = profileDir(),
  signal: AbortSignal = commandSignal,
): Promise<LogoutResult> {
  const lock = acquireProfileLock(dir);
  let operationFailed = false;
  let operationError: unknown;
  try {
    const remoteAlreadyRevoked = hasLogoutMarker(dir, lock);
    const session = readSession(dir, lock);
    const pending = readPendingSession(dir, lock);
    if (session && pending) {
      throw new StorageError("profile contains both complete and pending login state; inspect it before retrying");
    }
    const revocable = session ?? pending;
    if (revocable && !remoteAlreadyRevoked) {
      await requestServerLogout(
        revocable,
        DEFAULT_LOGOUT_TIMEOUT_MS,
        signal,
        (credentials) => {
          if (session) {
            writeSessionUnlocked({ ...session, ...credentials }, dir, lock);
          } else if (pending) {
            writePendingSessionUnlocked({ ...pending, ...credentials }, dir, lock);
          }
        },
      );
    }
    // The marker makes a retry idempotent: a successful remote revoke must
    // never force the user to present the old access token again merely
    // because local deletion was interrupted.
    if (revocable || remoteAlreadyRevoked) finishRemoteLogout(dir, lock);
    else clearProfileUnlocked(dir, {}, lock);
    return {
      hadSession: revocable !== null,
      serverLogout: revocable || remoteAlreadyRevoked ? "revoked" : "not-needed",
    };
  } catch (error) {
    operationFailed = true;
    operationError = error;
    throw error;
  } finally {
    if (operationFailed) throwWithLockReleaseFailure(lock, operationError);
    lock.release();
  }
}
