/**
 * `src/core/oidc.ts`'s `discoverOidcIssuer()` calls matrix-js-sdk's
 * `MatrixClient.getAuthMetadata()`, which internally constructs
 * oidc-client-ts state requiring `window.sessionStorage`/`window.
 * localStorage` to exist — a real browser has both natively; plain Node does
 * not, so under Node it throws `ReferenceError: window is not defined`
 * before ever making the HTTP request. Confirmed by direct testing — this is
 * a genuine gap in matrix-js-sdk's OIDC helpers for non-browser consumers,
 * not a misconfiguration on our side. (The same root cause is why we
 * deliberately do NOT use matrix-js-sdk's `OidcTokenRefresher` for token
 * refresh — see `core/oidc.ts`'s `refreshOidcToken`/`buildTokenRefreshFunction`,
 * a plain hand-rolled `fetch` instead, which needs no `window` at all and so
 * has no such gap, no matter when a refresh happens to fire.)
 *
 * `withOidcWindowShim()` installs a minimal in-memory `Storage`-shaped
 * `window` stub, runs `fn`, then removes it again — DELIBERATELY SCOPED, not
 * a permanent global assignment:
 *
 * A permanent `globalThis.window` breaks something unrelated —
 * `@matrix-org/matrix-sdk-crypto-wasm`'s own environment detection
 * (`typeof window !== "undefined"` → assumes a real browser IndexedDB is
 * available) fails with "Unsupported environment" once `window` exists at
 * all, even as an empty-ish stub, since the CLI's whole crypto-persistence
 * design (docs/DECISIONS.md D1) depends on Node being detected as Node
 * (`fake-indexeddb`), not as a browser. Confirmed by direct testing:
 * `initRustCrypto()` broke the moment `globalThis.window` was defined
 * unconditionally at module load.
 *
 * This is safe to use ONLY around `discoverOidcIssuer()`, and ONLY at OIDC
 * login time (`src/cli/oidc.ts`'s `runDeviceCodeLogin`) — the one call site
 * where it runs before any `TeleCryptIOStorage`/`MatrixClient`/rust-crypto
 * WASM exists in the process, so there is no concurrent WASM environment
 * check for the temporary stub to corrupt. Never wrap anything that runs
 * concurrently with, or after, crypto initialisation.
 */
class MemoryStorage implements Storage {
  private map = new Map<string, string>();

  get length(): number {
    return this.map.size;
  }

  clear(): void {
    this.map.clear();
  }

  getItem(key: string): string | null {
    return this.map.has(key) ? this.map.get(key)! : null;
  }

  key(index: number): string | null {
    return [...this.map.keys()][index] ?? null;
  }

  removeItem(key: string): void {
    this.map.delete(key);
  }

  setItem(key: string, value: string): void {
    this.map.set(key, value);
  }
}

export async function withOidcWindowShim<T>(fn: () => Promise<T>): Promise<T> {
  const hadWindow = "window" in globalThis;
  const previous = (globalThis as Record<string, unknown>).window;
  if (!hadWindow) {
    (globalThis as unknown as { window: { sessionStorage: Storage; localStorage: Storage } }).window = {
      sessionStorage: new MemoryStorage(),
      localStorage: new MemoryStorage(),
    };
  }
  try {
    return await fn();
  } finally {
    if (!hadWindow) {
      delete (globalThis as Record<string, unknown>).window;
    } else {
      (globalThis as Record<string, unknown>).window = previous;
    }
  }
}
