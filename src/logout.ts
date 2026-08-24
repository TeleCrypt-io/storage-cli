import { StorageError } from "@telecrypt-io/storage/core";
import {
  acquireProfileLock,
  clearProfileUnlocked,
  hasLogoutMarker,
  readPendingSession,
  readSession,
  profileDir,
  writeLogoutMarkerUnlocked,
  writePendingSessionUnlocked,
  writeSessionUnlocked,
  isBoundedOpaqueValue,
} from "./profile.js";
import type { ProfileLock } from "./profile.js";
import { assertOidcEndpoint, assertTrustedHomeserver } from "./oidc.js";
import {
  cancelReadableStreamReaderWithinBound,
  commandSignal,
  readReadableStreamChunkWithAbort,
  settlePromiseWithin,
} from "./cancellation.js";

const DEFAULT_LOGOUT_TIMEOUT_MS = 10_000;
const MAX_LOGOUT_TIMEOUT_MS = 120_000;
const MAX_LOGOUT_RESPONSE_BYTES = 64 * 1024;

async function consumeLogoutResponse(
  response: Response,
  controller: AbortController,
  readSignal: AbortSignal = controller.signal,
): Promise<unknown> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null && Number.isFinite(Number(declaredLength)) && Number(declaredLength) > MAX_LOGOUT_RESPONSE_BYTES) {
    const error = new StorageError("server logout response exceeds the output limit");
    controller.abort(error);
    throw error;
  }
  if (!response.body) return undefined;
  const reader = response.body.getReader();
  const cancellationError = new StorageError("server logout response read cancelled");
  let total = 0;
  const chunks: Uint8Array[] = [];
  let readFailed = false;
  try {
    while (true) {
      const chunk = await readReadableStreamChunkWithAbort(reader, readSignal, cancellationError);
      if (chunk.done) break;
      total += chunk.value.byteLength;
      if (total > MAX_LOGOUT_RESPONSE_BYTES) {
        const error = new StorageError("server logout response exceeds the output limit");
        controller.abort(error);
        await cancelReadableStreamReaderWithinBound(reader);
        throw error;
      }
      chunks.push(chunk.value);
    }
  } catch (error) {
    readFailed = true;
    throw error;
  } finally {
    try {
      reader.releaseLock();
    } catch (error) {
      // Preserve the body/cancellation error if a non-conforming reader
      // rejects releaseLock while a read request is still pending.
      if (!readFailed) throw error;
    }
  }
  if (chunks.length === 0) return undefined;
  try {
    return JSON.parse(Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8")) as unknown;
  } catch {
    return undefined;
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
    boundaryError = new StorageError("server logout request timed out");
    controller.abort(boundaryError);
    rejectBoundary(boundaryError);
  }, timeoutMs);
  const requestLogout = async (accessToken: string): Promise<{ status: number; body: unknown }> => {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}` },
      redirect: "manual",
      signal: controller.signal,
    });
    if (response.url !== endpoint) {
      controller.abort();
      throw new StorageError("server logout redirected unexpectedly");
    }
    const body = await consumeLogoutResponse(response, controller);
    return { status: response.status, body };
  };
  const operation = (async () => {
    let credentials: LogoutCredentials = session;
    let logoutResponse = await requestLogout(credentials.accessToken);
    if (logoutResponse.status === 200 || logoutResponse.status === 204) return;
    if (!isUnknownAccessTokenResponse(logoutResponse.status, logoutResponse.body)) {
      throw new StorageError(`server logout failed (HTTP ${logoutResponse.status})`);
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
      controller.abort();
      throw new StorageError("OIDC token refresh redirected unexpectedly");
    }
    // A fetch implementation may ignore the deadline's abort and deliver a
    // refresh response during the bounded cleanup join. Let its already
    // available body be consumed so rotated credentials can still be
    // persisted while the join owns the operation. The join still bounds a
    // body that never settles, and the callback is disabled once it ends.
    const lateRefreshSignal = boundaryError?.message === "server logout request timed out"
      ? new AbortController().signal
      : controller.signal;
    const refreshBody = await consumeLogoutResponse(refreshResponse, controller, lateRefreshSignal);
    if (
      refreshResponse.status === 400 &&
      refreshBody &&
      typeof refreshBody === "object" &&
      (refreshBody as { error?: unknown }).error === "invalid_grant"
    ) {
      return;
    }
    if (refreshResponse.status !== 200) {
      throw new StorageError(`OIDC token refresh failed (HTTP ${refreshResponse.status})`);
    }
    credentials = refreshedCredentials(credentials, refreshBody);
    if (acceptRefreshedCredentials) {
      onRefreshed?.(credentials as RefreshedLogoutCredentials);
    }
    logoutResponse = await requestLogout(credentials.accessToken);
    if (logoutResponse.status !== 200 && logoutResponse.status !== 204) {
      throw new StorageError(`server logout failed (HTTP ${logoutResponse.status})`);
    }
  })();
  // The boundary below may return before a broken fetch implementation
  // settles. Observe the operation immediately so a late rejection remains
  // handled after this command has reported its bounded failure.
  operation.catch(() => undefined);
  try {
    await Promise.race([operation, boundary]);
    if (boundaryError) throw boundaryError;
    if (externalSignal?.aborted) throw new StorageError("server logout cancelled");
  } catch (error) {
    if (boundaryError) {
      await settlePromiseWithin(operation);
      // Keep accepting a rotated refresh token only while this bounded join
      // still owns the profile lock. Once the join ends, a non-cooperative
      // operation may outlive the caller and must not write through a closed
      // transaction on a later retry.
      acceptRefreshedCredentials = false;
      throw boundaryError;
    }
    if (externalSignal?.aborted) throw new StorageError("server logout cancelled");
    if (error instanceof StorageError) throw error;
    throw new StorageError("server logout request failed");
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
  } catch {
    try {
      clearProfileUnlocked(dir, {}, heldLock);
      return;
    } catch {
      throw new StorageError("server logout succeeded but local cleanup is incomplete — retry logout");
    }
  }
  try {
    // Keep the marker in place while checking the rest of the profile. If an
    // unexpected entry makes cleanup incomplete, a retry can still prove that
    // the remote session was already revoked without using the old token.
    clearProfileUnlocked(dir, { preserveLogoutMarker: true }, heldLock);
  } catch {
    throw new StorageError("server logout succeeded but local cleanup is incomplete — retry logout");
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
  } finally {
    lock.release();
  }
}
