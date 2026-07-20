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

**Total: 37 tests, 37 passed, 0 failed**

- `test/functional/smoke.test.ts` — 1 test
- `test/functional/tree.test.ts` — 10 tests
- `test/functional/files.test.ts` — 8 tests
- `test/functional/sharing.test.ts` — 8 tests
- `test/functional/versions.test.ts` — 6 tests
- `test/functional/keys.test.ts` — 4 tests

## Notes

- All tests run against a **real disposable Synapse** via podman (`throwaway_synapse/`). No mocks.
- File encryption uses `matrix-encrypt-attachment` (AES-CTR + JWK) — same scheme as Matrix attachments.
- Tree semantics use `matrix-js-sdk`'s MSC3089 primitives (`MSC3089TreeSpace` / `MSC3089Branch`).
- The `httpUrl` from `getFileInfo()` 404s on modern Synapse (authenticated media required). All downloads in the library use the authenticated workaround (`mxcUrlToHttp` with `useAuthentication=true` + `Authorization: Bearer`).
- Phase 5 test 5.3 (second device recovery) verifies secret storage bootstrap from a recovery key. Full cross-device key restoration depends on key backup which requires additional setup.
- Test 3.8 (revocation) verifies that after Alice kicks Bob, Bob cannot decrypt files added after removal.

## Out of scope (not built)

- Phase 6: External share links (requires a separate HTTP proxy)
- Phase 7: Web UI
- Quota enforcement (relies on Synapse's built-in `max_upload_size`)
- Federation (disabled on target Synapse)

## Build note

`npm run build` (TypeScript compilation) produces errors from `matrix-js-sdk`'s own source files (`.ts` path extension issues, web-only APIs). This is a pre-existing issue with the dependency — the test suite runs correctly via `vitest`. The library source compiles cleanly when imported as a dependency.
