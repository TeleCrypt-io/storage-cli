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

## Test results

**Total: 37 tests, 37 passed, 0 failed** (test 4.6 is known-flaky — see below)

- `test/functional/smoke.test.ts` — 1 test
- `test/functional/tree.test.ts` — 10 tests
- `test/functional/files.test.ts` — 8 tests
- `test/functional/sharing.test.ts` — 8 tests
- `test/functional/versions.test.ts` — 6 tests
- `test/functional/keys.test.ts` — 4 tests

`npm run lint` and `npm run build` also pass clean (see Build note below —
the previous note in this file describing build errors was inaccurate).

## Notes

- All tests run against a **real disposable Synapse** via podman (`throwaway_synapse/`). No mocks.
- File encryption uses `matrix-encrypt-attachment` (AES-CTR + JWK) — same scheme as Matrix attachments.
- Tree semantics use `matrix-js-sdk`'s MSC3089 primitives (`MSC3089TreeSpace` / `MSC3089Branch`).
- The `httpUrl` from `getFileInfo()` 404s on modern Synapse (authenticated media required). All downloads in the library use the authenticated workaround (`mxcUrlToHttp` with `useAuthentication=true` + `Authorization: Bearer`).
- Phase 5 test 5.3 (second device recovery) verifies secret storage bootstrap from a recovery key. Full cross-device key restoration depends on key backup which requires additional setup.
- Test 3.8 (revocation) genuinely proves key-denial: Bob cannot decrypt "AFTER removal" via the library, via a direct low-level room-event fetch (denied by Synapse), or by attempting to decrypt the raw ciphertext (which he *can* fetch — media isn't ACL'd — but not decrypt, since he never obtains the AES key). An earlier version of this test only checked room membership, which proved the kick worked but not that E2EE key-denial worked; fixed 2026-07-20.
- Test 4.6 (fresh-client version history) requires a **persistent** crypto store to mean anything — the harness's default `useIndexedDB: false` makes "fresh client, same user" crypto-amnesiac (in-memory store discarded on restart), so it could never have recovered real history no matter what `getVersionHistory()` did. Fixed 2026-07-20 by scoping `useIndexedDB: true` (via `fake-indexeddb`, dev-dependency) to just this test. This is a genuine but incomplete fix: it recovers all 3 versions in ~9 of 10 runs; the rest recover only 2, apparently due to an upstream timing issue in when `matrix-js-sdk`'s rust crypto backend persists the ratchet state needed to re-decrypt one's own past messages. Full detail and next steps in `BLOCKERS.md`.

## Out of scope (not built)

- Phase 6: External share links (requires a separate HTTP proxy)
- Phase 7: Web UI
- Quota enforcement (relies on Synapse's built-in `max_upload_size`)
- Federation (disabled on target Synapse)

## Build note

Previously this section claimed `npm run build` produced errors from `matrix-js-sdk`'s own source files. That was unverified and turned out to be wrong: `tsconfig.json` only includes `src/**/*.ts` (not `test/`) and has `skipLibCheck: true`, so `matrix-js-sdk`'s declaration files were never actually being checked. The one real error was in our own `src/SecureStorage.ts` (an unsafe cast from `Record<string, unknown>` straight to `IEncryptedFile` for `decryptAttachment()`'s second argument, which TypeScript correctly flags as needing to go through `unknown` first) — fixed 2026-07-20. `npm run build` now passes clean.

Separately, `eslint.config.js` did not exist at all before 2026-07-20 (this project had `eslint` as a devDependency but no config, so `npm run lint` failed outright with "ESLint couldn't find an eslint.config.js"). Added a minimal flat config for `@typescript-eslint`'s recommended rules, with `no-unused-vars` configured to respect this codebase's existing `_`-prefix-means-intentionally-unused convention and `no-explicit-any` turned off (matrix-js-sdk's MSC3089 types are frequently too narrow for how the tests exercise them, and the tests already leaned on `any` pervasively before lint ever ran). `npm run lint` now passes clean.
