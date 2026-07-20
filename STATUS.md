# STATUS — TeleCrypt Secure Storage

**Date:** 2026-07-20

## Phases complete

| Phase | Description | Status |
|---|---|---|
| 0 | Test harness (disposable Synapse, user provisioning, client sessions, smoke test) | ✅ |
| 1 | Core tree operations — `SecureStorage` class, tree CRUD, listing, discovery | ✅ |
| 2 | Encrypted files — upload/download, byte-identical round-trip, mimetype, server never sees plaintext | ✅ |
| 3 | Sharing and access control — invite, permissions, viewer/editor, revocation | ✅ |
| 4 | Versioning — version history, old version download, listFiles vs listAllFiles, fresh-client history | ✅ |
| 5 | Key management — cross-signing bootstrap, secret storage, recovery key generation and decoding | ✅ |
| 5B | **Real key recovery** — server-side Secure Backup + restore on a genuinely new device (the "lost laptop" case) | ✅ |

## Phase 5B — real key recovery (this session)

Closed the gap documented in `docs/PHASE_5B_KEY_RECOVERY.md`: Phase 5 built cross-signing
bootstrap and recovery-key *generation*, but never built server-side key backup or restore,
so a genuinely new device could never actually recover old files. Tests 5.3/5.4 had been
softened to hide this.

**Two things changed:**

1. **`SecureStorage.create(opts)`** — the new recommended entry point (`src/SecureStorage.ts`).
   Builds the `MatrixClient`, calls `initRustCrypto` with a **persistent** crypto store
   (IndexedDB) **by default** — this replaces the old amnesiac `useIndexedDB: false` default
   that let the missing-recovery gap slip in unnoticed. Wires `cryptoCallbacks` so the `keys`
   API works out of the box, starts the client, waits for first sync, returns a ready
   `SecureStorage`. The plain constructor (`new SecureStorage(client)`) still exists for
   advanced callers who build/configure the `MatrixClient` themselves; `keys.*` only works
   there if the caller wires an equivalent `cryptoCallbacks` object at `createClient()` time
   (matrix-js-sdk fixes that object reference at construction — it cannot be added after
   `initRustCrypto()` has run).

2. **`storage.keys` API** — `setupRecovery()`, `isRecoverySetup()`, `restoreFromRecoveryKey()`.
   `setupRecovery()` calls `bootstrapCrossSigning`, then `bootstrapSecretStorage({
   setupNewSecretStorage: true, setupNewKeyBackup: true, createSecretStorageKey })` (which
   internally calls `resetKeyBackup()` and starts the backup engine), then
   `checkKeyBackupAndEnable()`, and returns the Recovery Key string. `restoreFromRecoveryKey()`
   decodes the key, unlocks secret storage via a temporary `getSecretStorageKey` callback,
   calls `loadSessionBackupPrivateKeyFromSecretStorage()` then `restoreKeyBackup()`, and
   returns `{ imported, total }`. Both paths throw clear, prefixed errors (never silently
   "succeed") on a malformed or wrong recovery key. See `src/SecureStorage.ts` for full
   implementation and doc comments.

**Harness:** `loginNewDevice(user)` (`test/harness/users.ts`) does a real
`POST /_matrix/client/v3/login` with `m.login.password`, returning a second `TestUser` with a
new `device_id` + `access_token` for the same account — the "new laptop."

**Tests 5.3/5.4 rewritten to their strong form** (`test/functional/keys.test.ts`):
- **5.3** — Device A uploads a file and runs `setupRecovery()`. The test polls
  `isRecoverySetup()` (backup engine believes it's active) **and** the raw server endpoint
  `GET /room_keys/version` for `count >= 1` (the file's room key has actually reached the
  server — `isRecoverySetup()` alone only proves the engine is running, not that this specific
  session uploaded). Device B = `loginNewDevice` + `create()`. **Negative control:** asserts
  device B **cannot** decrypt the file yet — verified in logs as a genuine rust-crypto
  `DecryptionError: This message was sent before this device logged in, and key backup is not
  working`, not a mocked/skipped check. Then `restoreFromRecoveryKey(recoveryKey)`, and polls
  for device B to decrypt the file to bytes identical to what device A uploaded.
- **5.4** — device B with a garbage string (fails at `decodeRecoveryKey`, before any network
  call) and with a well-formed-but-wrong recovery key (a genuine key from an unrelated
  throwaway account) both throw from `restoreFromRecoveryKey`, and device B still cannot
  decrypt the file afterward.
- **5.1/5.2** simplified to exercise the `keys` API directly (`setupRecovery()` returns a
  decodable 32-byte key and `isRecoverySetup()` transitions false → true).

**Device isolation:** each `create()`d client gets its own IndexedDB store, prefixed by
`secure-storage::<userId>::<deviceId>` (overridable). This matters even outside of tests: the
rust crypto backend's default store prefix is a single fixed constant, so two different
device sessions sharing one IndexedDB origin (as happens in this repo's tests, since
`fake-indexeddb` is process-global) would otherwise silently share one crypto store. Device
B's negative control in 5.3 is what would catch a regression here.

No blockers — Layer 2 worked end-to-end against this Synapse. No `BLOCKERS.md` was needed.

## Test results

**Total: 37 tests, 37 passed, 0 failed.** Verified deterministically this session: 5 standalone
runs of `keys.test.ts` (the new 5.3/5.4 recovery tests, timings ranging ~2.5s–11s per run,
confirming the polling is doing real waiting rather than getting lucky) plus 3 full-suite runs,
all green. (Also previously verified: 15 consecutive standalone runs of test 4.6, plus 3
full-suite runs, all green.)

- `test/functional/smoke.test.ts` — 1 test
- `test/functional/tree.test.ts` — 10 tests
- `test/functional/files.test.ts` — 8 tests
- `test/functional/sharing.test.ts` — 8 tests
- `test/functional/versions.test.ts` — 6 tests
- `test/functional/keys.test.ts` — 4 tests (5.1/5.2 bootstrap primitives via the `keys` API;
  5.3/5.4 real cross-device recovery — see Phase 5B above)

`npm run lint` and `npm run build` also pass clean (see Build note below —
the previous note in this file describing build errors was inaccurate).

## Notes

- All tests run against a **real disposable Synapse** via podman (`throwaway_synapse/`). No mocks.
- File encryption uses `matrix-encrypt-attachment` (AES-CTR + JWK) — same scheme as Matrix attachments.
- Tree semantics use `matrix-js-sdk`'s MSC3089 primitives (`MSC3089TreeSpace` / `MSC3089Branch`).
- The `httpUrl` from `getFileInfo()` 404s on modern Synapse (authenticated media required). All downloads in the library use the authenticated workaround (`mxcUrlToHttp` with `useAuthentication=true` + `Authorization: Bearer`).
- **Recommended entry point is now `SecureStorage.create(opts)` + `storage.keys.*`** (Phase 5B, this session), not the bare constructor — see "Phase 5B" above. The old note that lived here ("full cross-device key restoration depends on key backup which requires additional setup") is what this session's work resolved.
- Deep-importing matrix-js-sdk internals (`decodeRecoveryKey`, `CryptoCallbacks`) from `src/SecureStorage.ts` must go through the **compiled** `matrix-js-sdk/lib/...` path, not `matrix-js-sdk/src/...`. The `src/` tree's own relative imports use literal `.ts` extensions (their build setup allows it); pulling that into our `tsc` build (which lacks `allowImportingTsExtensions`) makes `tsc` fully type-check matrix-js-sdk's entire source tree and fail with hundreds of unrelated errors, since `skipLibCheck` only skips `.d.ts` files. `matrix-js-sdk/lib/...` is proper compiled output (`.js` + `.d.ts`), so `skipLibCheck` applies normally. Test files are unaffected (not part of the `tsc` build; vitest's esbuild transform doesn't type-check), which is why the pre-existing `test/functional/keys.test.ts` deep-`src/` import was never a problem before this session added a deep import to `src/SecureStorage.ts` itself.
- Test 3.8 (revocation) genuinely proves key-denial: Bob cannot decrypt "AFTER removal" via the library, via a direct low-level room-event fetch (denied by Synapse), or by attempting to decrypt the raw ciphertext (which he *can* fetch — media isn't ACL'd — but not decrypt, since he never obtains the AES key). An earlier version of this test only checked room membership, which proved the kick worked but not that E2EE key-denial worked; fixed 2026-07-20.
- Test 4.6 (fresh-client version history) requires a **persistent** crypto store to mean anything — the harness's default `useIndexedDB: false` makes "fresh client, same user" crypto-amnesiac (in-memory store discarded on restart), so it could never have recovered real history no matter what `getVersionHistory()` did. Fixed 2026-07-20 by scoping `useIndexedDB: true` (via `fake-indexeddb`, dev-dependency) to just this test, plus polling for the full 3-version chain (re-fetching the branch and calling `getVersionHistory()` each iteration) instead of asserting on the first read — the chain walk depends on v2/v3 finishing local decryption and relation aggregation, which is asynchronous and can still be settling right after the (unencrypted) branch state events land. The initial version of this fix (persistence alone, first-read assertion) was flaky (~1-in-10 runs recovered only 2 of 3 versions); adding the poll made it deterministic across 15 consecutive runs. Note this genuinely depends on the chain being recoverable — if key-denial were real, the poll times out and the test fails, it doesn't mask anything.
- An earlier hypothesis for 4.6's root cause — that `getVersionHistory()` only scans the live timeline without paginating, and a shallow `initialSyncLimit: 10` sync misses older events — was tested (forced `client.scrollback()`) and disproved: the fresh client's first `/sync` already contained all 19 timeline events for the room. The actual cause was crypto-store persistence + decryption-settling timing, not pagination.

## Out of scope (not built)

- Phase 6: External share links (requires a separate HTTP proxy)
- Phase 7: Web UI
- Quota enforcement (relies on Synapse's built-in `max_upload_size`)
- Federation (disabled on target Synapse)

## Build note

Previously this section claimed `npm run build` produced errors from `matrix-js-sdk`'s own source files. That was unverified and turned out to be wrong: `tsconfig.json` only includes `src/**/*.ts` (not `test/`) and has `skipLibCheck: true`, so `matrix-js-sdk`'s declaration files were never actually being checked. The one real error was in our own `src/SecureStorage.ts` (an unsafe cast from `Record<string, unknown>` straight to `IEncryptedFile` for `decryptAttachment()`'s second argument, which TypeScript correctly flags as needing to go through `unknown` first) — fixed 2026-07-20. `npm run build` now passes clean.

Separately, `eslint.config.js` did not exist at all before 2026-07-20 (this project had `eslint` as a devDependency but no config, so `npm run lint` failed outright with "ESLint couldn't find an eslint.config.js"). Added a minimal flat config for `@typescript-eslint`'s recommended rules, with `no-unused-vars` configured to respect this codebase's existing `_`-prefix-means-intentionally-unused convention and `no-explicit-any` turned off (matrix-js-sdk's MSC3089 types are frequently too narrow for how the tests exercise them, and the tests already leaned on `any` pervasively before lint ever ran). `npm run lint` now passes clean.
