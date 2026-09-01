# TeleCrypt.io Storage CLI

The command-line interface for TeleCrypt.io end-to-end encrypted Matrix storage.

The CLI runs on Linux and requires Node.js `>=24.20.0`; release tooling verifies that exact Node.js
version and the bundled npm `11.19.0`.

It consumes one exact public `@telecrypt-io/storage` library version and provides the
`telecrypt-io storage` command group: login, recovery, shared vaults and nested folders, and file
upload, download, rename, and deletion. Its real-stack Harness scenarios exercise these same SDK
operations as the web UI; they are operator-local acceptance tests, never hosted CI.

**Distribution:** the standalone CLI is available only as an exact
[GitHub Release](https://github.com/TeleCrypt-io/storage-cli/releases), never from the NPM registry.

## Install

```bash
npm install -g --ignore-scripts https://github.com/TeleCrypt-io/storage-cli/releases/download/storage-cli-vX.Y.Z/storage-cli-vX.Y.Z.tgz
```

Replace `X.Y.Z` with an existing release version. `npm` is used only as the Node installer: the
archive and its bundled runtime dependencies are fetched from GitHub, not from the NPM registry.
This installs the `telecrypt-io` executable. Existing download paths are never overwritten. The library source is in
[`TeleCrypt-io/storage-sdk`](https://github.com/TeleCrypt-io/storage-sdk).

## Usage

The CLI supports MAS/OIDC device authorization only; it never sends a Matrix login password.
Recovery-key setup/export is a supported product feature for restoring encrypted keys on a new
device. See the [canonical CLI reference](./CLI.md) for commands, profile handling, JSON output,
sharing, file operations, and recovery.

## Development

```bash
npm ci --ignore-scripts
npm run test:unit
```

Full Harness acceptance is local-only. Start the shared disposable Synapse/MAS fixture from a
Storage SDK checkout, then run `npm test` from this checkout. These scenarios connect to
`http://localhost:8008`; hosted Actions never runs them and they never target a production server.

See [CLI.md](./CLI.md) for the full command reference and [RELEASING.md](./RELEASING.md) for the
guarded GitHub Release procedure.

## Licence

[Business Source License 1.1](./LICENSE). Non-commercial use is permitted; converts to
Apache License 2.0 on 2030-07-20.

For commercial licensing, contact TeleCrypt.io.

## Third-party notices

The CLI bundles exact runtime dependencies. Each release archive includes a generated
`THIRD-PARTY-LICENSES.txt` inventory from the lockfile and verifies that every bundled package
contributes its own license file; use the copy inside the archive as the authoritative dependency
notice.
