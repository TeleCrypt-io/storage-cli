import { StorageError } from "@telecrypt-io/storage/core";
import {
  acquireProfileLock,
  assertFreshProfileUnlocked,
  profileDir,
  type PendingSession,
  readSession,
  throwWithLockReleaseFailure,
  writeSessionUnlocked,
  writePendingSessionUnlocked,
  type Session,
} from "./profile.js";
import { initStorageForNewSession } from "./storage.js";
import { OidcLoginError, runDeviceCodeLogin, type DeviceCodeLoginHooks } from "./oidc.js";
import { finishRemoteLogout, requestServerLogout } from "./logout.js";
import { commandSignal } from "./cancellation.js";
import { withCause } from "./failure.js";

/**
 * Runs authorization, session persistence, and first crypto initialization as
 * one fenced profile transaction. A failed initialization either revokes the
 * exact newly-issued remote session and removes its partial local state, or
 * leaves that session in place so `storage logout` can retry revocation.
 */
export async function loginAndInitialize(
  homeserver: string,
  hooks: DeviceCodeLoginHooks,
  signal: AbortSignal = commandSignal,
): Promise<Session> {
  const dir = profileDir();
  const lock = acquireProfileLock(dir);
  let session: Session | undefined;
  let sessionPersisted = false;
  let opened: Awaited<ReturnType<typeof initStorageForNewSession>> | undefined;
  let operationFailed = false;
  let operationError: unknown;
  let profilePreflightComplete = false;
  try {
    try {
      assertFreshProfileUnlocked(dir, lock);
      profilePreflightComplete = true;
      session = await runDeviceCodeLogin(homeserver, hooks, signal);
      writeSessionUnlocked(session, dir, lock);
      sessionPersisted = true;
      opened = await initStorageForNewSession(session, dir, lock, signal);
      await opened.close();
      return session;
    } catch (error) {
      if (!profilePreflightComplete) throw error;
      const recoveryFailures: unknown[] = [error];
      // If the initialization path reached `opened.close()`, its failure is
      // itself part of the primary transaction result. Keep it when the
      // recovery path below reports the final revocation outcome.
      if (opened) {
        try {
          await opened.close();
        } catch (closeError) {
          recoveryFailures.push(closeError);
        }
      }
      function throwLoginFailure(failure: unknown): never {
        const causes = recoveryFailures.filter((cause) => cause !== failure);
        const safeFailure = failure instanceof StorageError
          ? failure
          : new StorageError("login initialization failed");
        if (causes.length === 0 && safeFailure !== failure) causes.push(failure);
        if (causes.length > 0) {
          withCause(
            safeFailure,
            causes.length === 1 ? causes[0] : new AggregateError(causes, "login initialization failed"),
          );
        }
        throw safeFailure;
      }
      let latestSession: Session | undefined;
      if (sessionPersisted) {
        try {
          latestSession = readSession(dir, lock) ?? undefined;
        } catch (readError) {
          recoveryFailures.push(readError);
        }
      }
      const cleanupSession = latestSession ?? session;
      let pending: PendingSession | undefined =
        error instanceof OidcLoginError
          ? error.pendingSession
          : cleanupSession
            ? {
                homeserver: cleanupSession.homeserver,
                userId: cleanupSession.userId,
                matrixServerName: cleanupSession.matrixServerName,
                deviceId: cleanupSession.deviceId,
                accessToken: cleanupSession.accessToken,
                oidcIssuer: cleanupSession.oidcIssuer,
                refreshToken: cleanupSession.refreshToken,
                oidcClientId: cleanupSession.oidcClientId,
                oidcTokenEndpoint: cleanupSession.oidcTokenEndpoint,
                oidcRevocationEndpoint: cleanupSession.oidcRevocationEndpoint,
              }
            : undefined;
      if (!pending) throwLoginFailure(error);

      let markedForRetry = sessionPersisted;
      if (!markedForRetry) {
        try {
          writePendingSessionUnlocked(pending, dir, lock);
          markedForRetry = true;
        } catch (persistenceError) {
          recoveryFailures.push(persistenceError);
          // A persistence failure can be the reason this transaction failed.
          // Still attempt immediate revocation; if that also fails, report that
          // cleanup could not be made retryable rather than claiming success.
        }
      }

      let revoked = false;
      try {
        await requestServerLogout(
          pending,
          undefined,
          signal,
          (credentials) => {
            pending = { ...pending!, ...credentials };
            if (sessionPersisted && pending.userId && pending.matrixServerName) {
              writeSessionUnlocked(pending as Session, dir, lock);
            } else {
              writePendingSessionUnlocked(pending, dir, lock);
            }
          },
        );
        revoked = true;
      } catch (remoteLogoutError) {
        recoveryFailures.push(remoteLogoutError);
        // Keep the exact new session locally so logout can retry revocation.
      }
      if (!revoked) {
        if (!markedForRetry) {
          throwLoginFailure(new StorageError(
            "login initialization failed; server session could not be revoked and could not be saved for retry",
          ));
        }
        throwLoginFailure(new StorageError(
          "login initialization failed; server session retained for retry — run `storage logout` before trying again",
        ));
      }
      try {
        finishRemoteLogout(dir, lock);
      } catch (localCleanupError) {
        recoveryFailures.push(localCleanupError);
        throwLoginFailure(new StorageError(
          "login initialization failed after server revocation; local cleanup is incomplete — run `storage logout`",
        ));
      }
      throwLoginFailure(new StorageError("login initialization failed; server session was revoked — retry login"));
    }
  } catch (error) {
    operationFailed = true;
    operationError = error;
    throw error;
  } finally {
    if (operationFailed) throwWithLockReleaseFailure(lock, operationError);
    lock.release();
  }
}
