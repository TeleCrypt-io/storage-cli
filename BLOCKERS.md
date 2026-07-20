# Blockers

## Test 4.6 `versions.test.ts` — "fresh client recovers full version chain"

**Status:** Tightened to `expect(history.length).toBe(3)` (root-cause chain
`[3,2,1]` expected). This assertion is currently **flaky, not reliably
passing** — observed roughly 1-in-10 runs recovers only 2 of 3 versions
(the rest pass fully). Left failing/flaky intentionally, per instructions,
rather than weakened back to `toBeGreaterThanOrEqual(1)`.

### What the original (false-green) test hid

The original assertion `expect(history.length).toBeGreaterThanOrEqual(1)` is
trivially always true: `MSC3089Branch.getVersionHistory()` (in
`matrix-js-sdk`) always includes at least the branch it was called on. It
never actually proved the fresh client recovered any *history*.

### First hypothesis (disproved): timeline pagination depth

The task brief suggested the likely cause was `getVersionHistory()` only
scanning the live timeline (`room.getLiveTimeline().getEvents()`) without
paginating, combined with the harness's `initialSyncLimit: 10` giving a fresh
client a shallow timeline. I implemented and tested this fix (forcing
`client.scrollback()` until `room.oldState.paginationToken` was exhausted)
and it made **no difference** — I confirmed by instrumenting the test that
the fresh client's initial `/sync` already contained **all 19 timeline
events** for the room (room create through all 3 file-version state/message
events), so there was nothing left to paginate. This hypothesis was wrong.

### Actual root cause: E2EE key non-persistence across "fresh" client restarts

`test/harness/users.ts`'s `registerTestUser()` is called **once** per test,
so the "clientA" and "clientB" in 4.6 share the same `userId`/`deviceId`/
`accessToken` — this test is not simulating a second device, it's simulating
**the same device restarting**. `test/harness/clients.ts`'s
`createTestClient()` calls `client.initRustCrypto({ useIndexedDB: false })`,
which per `matrix-js-sdk`'s `client.ts` (`storePrefix: args.useIndexedDB ===
false ? null : ...`) uses a purely **in-memory** crypto store. When clientA
calls `stopTestClient()` (`client.stopClient()`), all of its megolm session
state is discarded. ClientB then starts with a **completely empty crypto
store** despite being "the same device" — every message clientA sent comes
back as `m.bad.encrypted`: `"This message was sent before this device
logged in, and there is no key backup on the server."` — confirmed by
instrumenting `getContent()` on the raw timeline events.

This is **not** what a real client does (a real client persists its crypto
store — IndexedDB in browsers — across restarts) and it is **not** a bug in
`getVersionHistory()` or in this library's `SecureStorage` wrapper; it's an
artifact of the test harness's `useIndexedDB: false` choice (made because
Node has no native IndexedDB and the harness otherwise runs in plain Node,
not jsdom).

### Attempted fix (partial, flaky — not committed as a full fix)

For test 4.6 only, I:
1. Added the `fake-indexeddb` dev dependency and imported `fake-indexeddb/auto`
   at the top of `versions.test.ts` only (scoped: vitest isolates each test
   file's global object by default, and every other `createTestClient()` call
   site across the suite still explicitly passes `useIndexedDB: false`, so
   this does not change behavior anywhere else).
2. Extended `createTestClient(user, opts?)` in `test/harness/clients.ts` with
   an optional `{ useIndexedDB?: boolean }` parameter (default `false`,
   preserving existing behavior everywhere else).
3. In 4.6 specifically, both clientA and clientB now use
   `{ useIndexedDB: true }`, so clientB opens the **same** persistent
   (fake-IndexedDB-backed) crypto store clientA wrote to.

This closed most of the gap — before: 1-of-3 versions ever recoverable
(only the metadata of the branch called on, no chain at all); after: usually
3 of 3, occasionally 2 of 3. It is **not fully reliable**, but it is now the
common case rather than the exception. Over 16 manual runs of just this test
(6 with ad hoc debug logging still present in the test body, 10 after that
logging was removed) it failed (`[2,1]` instead of `[3,2,1]`) 5 times —
1 failure in 10 with the debug logging removed, so the true baseline flake
rate is probably closer to that ~10% than the ~65% observed while extra
console.log/instrumentation work was slowing down the event loop during the
critical window. When it does fail, the oldest version (`v1`)'s own message
content is consistently `m.bad.encrypted` even when the *chain* still
resolves correctly (this makes sense: `getVersionHistory()`'s backward walk
uses the *newer* event's decrypted `m.relates_to` to link to the older one,
not the older event's own content — so v1's branch metadata can appear in
the chain even though its file body is separately undecryptable). What's
flaky is whether `v2`'s and `v3`'s own message content decrypt successfully
in time, which determines whether the v1↔v2 and v2↔v3 relation links get
established at all.

I suspect this is an upstream timing issue in how `matrix-js-sdk`'s rust
crypto backend (`matrix-sdk-crypto-wasm`) persists (or batches/queues the
persistence of) the ratchet state needed to locally re-decrypt one's own
previously-sent group-encrypted messages — i.e., whether the specific
session/ratchet checkpoint needed for message index N was flushed to the
IndexedDB-backed store before the client was torn down. Adding an explicit
1.5s sleep before `stopClient()` did **not** reliably fix it (still flaked
at a similar rate), so I removed that sleep rather than ship a superstitious
delay — timing-based waits without a real signal to wait on tend to just
hide the bug's frequency, not fix it.

### Why I stopped here

Per the task's own guidance, this was budgeted as **one bounded attempt**.
Chasing this further would mean either:
- Digging into `matrix-sdk-crypto-wasm`'s (Rust, WASM-compiled) internals to
  find/force a synchronous flush point — a significant time investment in a
  third-party dependency's internals, or
- Standing up real key-backup infrastructure (`bootstrapSecretStorage` +
  server-side megolm backup + restore-on-decrypt-failure) so a fresh client
  can pull keys from backup instead of relying on local persistence at
  all — explicitly flagged as **out of scope** already in `STATUS.md`
  ("Full cross-device key restoration depends on key backup which requires
  additional setup").

Both are real fixes but are feature work beyond "fix two false-green
tests," so per the task's explicit instructions this is left documented here
with the assertion at `toBe(3)` (failing/flaky) rather than weakened.

### If picked up later

The productive next step is almost certainly key backup (`bootstrapCrossSigning`
+ `bootstrapSecretStorage` + `crypto.getBackupInfo()`/restore flow — Phase 5
already has the cross-signing/secret-storage bootstrap building blocks in
`keys.test.ts`), which would make a fresh client's version-history recovery
correct and deterministic regardless of local crypto-store persistence
timing, matching how real E2EE clients handle "signed in on a new/reset
device."
