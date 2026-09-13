import {
  cancelResponseBody,
  readResponseBody,
  ResponseBodyReadError,
  StorageError,
} from "@telecrypt-io/storage/core";
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
  isOpaqueValue,
} from "./profile.js";
import type { ProfileLock } from "./profile.js";
import { assertOidcEndpoint, assertTrustedHomeserver } from "./oidc.js";
import { commandSignal } from "./cancellation.js";
import { safeDiagnosticText } from "./output.js";

const DEFAULT_LOGOUT_TIMEOUT_MS = 10_000;

async function consumeLogoutResponse(
  response: Response,
  readSignal: AbortSignal,
  operation: string,
): Promise<string> {
  try {
    const body = await readResponseBody(response, readSignal, {
      abortError: () => new StorageError(`${operation} response read cancelled`),
    });
    return new TextDecoder().decode(body.bytes);
  } catch (error) {
    if (!(error instanceof ResponseBodyReadError)) throw error;
    const partialText = safeDiagnosticText(new TextDecoder().decode(error.bytes));
    throw new StorageError(`${operation} response body could not be read (HTTP ${response.status})`, {
      cause: new Error(
        `${operation} response body: ${partialText || "<empty>"}`,
        { cause: error.cause },
      ),
    });
  }
}

function responseBodyFailure(operation: string, status: number, text: string, cause?: unknown): StorageError {
  return new StorageError(`${operation} failed (HTTP ${status})`, {
    cause: text === ""
      ? cause
      : new Error(`${operation} response body: ${safeDiagnosticText(text)}`, { cause }),
  });
}

function parseLogoutJson(operation: string, status: number, text: string): unknown {
  if (text === "") throw responseBodyFailure(operation, status, text);
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw responseBodyFailure(operation, status, text, error);
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
  return new StorageError("server logout succeeded but local cleanup is incomplete — retry logout", { cause });
}

function safeLogoutRequestFailure(error: unknown): StorageError {
  const primary = error instanceof AggregateError ? error.errors[0] : undefined;
  const message = primary instanceof StorageError ? primary.message : "server logout request failed";
  return new StorageError(message, { cause: error });
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
  if (!isOpaqueValue(response.access_token)) {
    throw new StorageError("OIDC refresh response contained an invalid access token");
  }
  const nextRefresh = response.refresh_token ?? session.refreshToken;
  if (!isOpaqueValue(nextRefresh)) {
    throw new StorageError("OIDC refresh response contained an invalid refresh token");
  }
  if (!isOpaqueValue(session.oidcClientId) || typeof session.oidcTokenEndpoint !== "string") {
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
  if (!isOpaqueValue(session.accessToken)) {
    throw new StorageError("server logout token is invalid");
  }

  const trustedHomeserver = assertTrustedHomeserver(session.homeserver);
  const issuer = new URL(assertOidcEndpoint(session.oidcIssuer, trustedHomeserver, "OIDC issuer"));
  const revocationEndpoint = session.oidcRevocationEndpoint !== undefined
    ? assertOidcEndpoint(
      session.oidcRevocationEndpoint,
      trustedHomeserver,
      "OIDC revocation endpoint",
      issuer,
    )
    : undefined;
  if (revocationEndpoint !== undefined && !isOpaqueValue(session.oidcClientId)) {
    throw new StorageError("persisted OIDC revocation state is incomplete");
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
  ): Promise<{ status: number; bodyText: string }> => {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}` },
      redirect: "manual",
      signal: controller.signal,
    });
    if (response.url !== endpoint) {
      const error = new StorageError("server logout redirected unexpectedly");
      controller.abort(error);
      cancelResponseBody(response);
      throw error;
    }
    const bodyText = await consumeLogoutResponse(response, controller.signal, "server logout");
    return { status: response.status, bodyText };
  };
  const requestOidcRevocation = async (): Promise<void> => {
    const response = await fetch(revocationEndpoint!, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        token: session.accessToken,
        token_type_hint: "access_token",
        client_id: session.oidcClientId!,
      }),
      redirect: "manual",
      signal: controller.signal,
    });
    if (response.url !== revocationEndpoint) {
      const error = new StorageError("OIDC revocation redirected unexpectedly");
      controller.abort(error);
      cancelResponseBody(response);
      throw error;
    }
    const bodyText = await consumeLogoutResponse(response, controller.signal, "OIDC revocation");
    if (response.status !== 200) {
      throw responseBodyFailure("OIDC revocation", response.status, bodyText);
    }
  };
  const operation = (async () => {
    if (revocationEndpoint !== undefined) {
      await requestOidcRevocation();
      return;
    }
    let credentials: LogoutCredentials = session;
    let logoutResponse = await requestLogout(credentials.accessToken);
    if (logoutResponse.status === 200 || logoutResponse.status === 204) return;
    if (logoutResponse.status !== 401) {
      throw responseBodyFailure("server logout", logoutResponse.status, logoutResponse.bodyText);
    }
    const logoutBody = parseLogoutJson("server logout", logoutResponse.status, logoutResponse.bodyText);
    if (!isUnknownAccessTokenResponse(logoutResponse.status, logoutBody)) {
      throw responseBodyFailure("server logout", logoutResponse.status, logoutResponse.bodyText);
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
      cancelResponseBody(refreshResponse);
      throw error;
    }
    const refreshText = await consumeLogoutResponse(refreshResponse, controller.signal, "OIDC token refresh");
    if (refreshResponse.status === 400 && refreshText !== "") {
      try {
        const body = JSON.parse(refreshText) as unknown;
        if (body && typeof body === "object" &&
            (body as { error?: unknown }).error === "invalid_grant") return;
      } catch {
        // The ordinary HTTP error below includes the malformed body and status.
      }
    }
    if (refreshResponse.status !== 200) {
      throw responseBodyFailure("OIDC token refresh", refreshResponse.status, refreshText);
    }
    const refreshBody = parseLogoutJson("OIDC token refresh", refreshResponse.status, refreshText);
    try {
      credentials = refreshedCredentials(credentials, refreshBody);
    } catch (error) {
      throw responseBodyFailure("OIDC token refresh", refreshResponse.status, refreshText, error);
    }
    if (acceptRefreshedCredentials) {
      onRefreshed?.(credentials as RefreshedLogoutCredentials);
    }
    logoutResponse = await requestLogout(credentials.accessToken);
    if (logoutResponse.status !== 200 && logoutResponse.status !== 204) {
      throw responseBodyFailure("server logout", logoutResponse.status, logoutResponse.bodyText);
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
      throw new StorageError("server logout cancelled", { cause: error });
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
      clearProfileUnlocked(dir, heldLock);
      return;
    } catch (localCleanupError) {
      throw localLogoutCleanupError(new AggregateError(
        [markerError, localCleanupError],
        "server logout local cleanup failed",
      ));
    }
  }
  try {
    // Remove the marker last so an interrupted cleanup can be retried without
    // presenting the revoked token again.
    clearProfileUnlocked(dir, heldLock);
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
    else clearProfileUnlocked(dir, lock);
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
