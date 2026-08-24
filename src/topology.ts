/**
 * The only Matrix homeserver identities supported by the CLI. Keep this
 * topology finite: a user-provided HTTPS hostname must never become an
 * implicit bearer-token destination.
 */
export const TELECRYPT_HOMESERVERS = Object.freeze({
  production: Object.freeze({
    hostname: "backend.telecrypt.io",
    homeserver: "https://backend.telecrypt.io",
    serverName: "telecrypt.io",
  }),
  stage: Object.freeze({
    hostname: "backend.stage.telecrypt.io",
    homeserver: "https://backend.stage.telecrypt.io",
    serverName: "stage.telecrypt.io",
  }),
});

export const LOOPBACK_HOSTNAMES = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);
export const LOCAL_HOMESERVER_SERVER_NAME = "example.test";

export function isExactLoopbackHost(hostname: string): boolean {
  return LOOPBACK_HOSTNAMES.has(hostname);
}

/** Returns the independently trusted Matrix server name for a supported URL. */
export function expectedMatrixServerName(homeserver: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(homeserver);
  } catch {
    return null;
  }
  if (
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.pathname !== "/" ||
    (homeserver !== parsed.origin && homeserver !== `${parsed.origin}/`)
  ) {
    return null;
  }
  if (isExactLoopbackHost(parsed.hostname)) {
    return parsed.protocol === "http:" ? LOCAL_HOMESERVER_SERVER_NAME : null;
  }
  if (parsed.protocol !== "https:" || parsed.port !== "") return null;
  for (const profile of Object.values(TELECRYPT_HOMESERVERS)) {
    if (parsed.hostname === profile.hostname) return profile.serverName;
  }
  return null;
}
