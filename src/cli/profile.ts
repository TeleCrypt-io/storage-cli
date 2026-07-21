import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

export interface Session {
  homeserver: string;
  userId: string;
  deviceId: string;
  accessToken: string;
  /**
   * Present only when logged in via `storage login --oidc` (device-code
   * grant against MAS — see src/cli/oidc.ts and docs/OAUTH_SPEC.md Part C).
   * Absent for a plain password login. `oidcTokenEndpoint` is persisted
   * directly (rather than re-discovered from `oidcIssuer` on every command)
   * so reusing/refreshing the session never needs OIDC discovery again —
   * discovery is Node-hostile (see src/cli/oidcWindowPolyfill.ts) and this
   * avoids needing it more than once, at login time.
   */
  refreshToken?: string;
  oidcIssuer?: string;
  oidcClientId?: string;
  oidcTokenEndpoint?: string;
}

/**
 * Resolves the profile directory: everything this CLI persists (session,
 * crypto store) lives here. Overridable via TELECRYPT_IO_STORAGE_HOME so
 * tests can give each simulated user/device its own isolated profile.
 * Defaults to ~/.telecrypt-io/storage for normal interactive use.
 */
export function profileDir(): string {
  const home = process.env.TELECRYPT_IO_STORAGE_HOME;
  if (home && home.trim() !== "") return home;
  return path.join(os.homedir(), ".telecrypt-io", "storage");
}

export function sessionPath(dir: string = profileDir()): string {
  return path.join(dir, "session.json");
}

export function cryptoSnapshotPath(dir: string = profileDir()): string {
  return path.join(dir, "crypto.snapshot");
}

export function ensureProfileDir(dir: string = profileDir()): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
}

export function readSession(dir: string = profileDir()): Session | null {
  const p = sessionPath(dir);
  if (!fs.existsSync(p)) return null;
  const raw = fs.readFileSync(p, "utf8");
  return JSON.parse(raw) as Session;
}

export function writeSession(session: Session, dir: string = profileDir()): void {
  ensureProfileDir(dir);
  fs.writeFileSync(sessionPath(dir), JSON.stringify(session, null, 2), {
    mode: 0o600,
  });
}

/** Clears all local state for this profile (session + crypto store). */
export function clearProfile(dir: string = profileDir()): void {
  const sp = sessionPath(dir);
  const cp = cryptoSnapshotPath(dir);
  if (fs.existsSync(sp)) fs.rmSync(sp);
  if (fs.existsSync(cp)) fs.rmSync(cp);
}
