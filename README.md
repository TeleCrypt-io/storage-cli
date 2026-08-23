# TeleCrypt.io Storage CLI

The command-line interface for TeleCrypt.io end-to-end encrypted Matrix storage.

It consumes one exact public `@telecrypt-io/storage` library version and provides the
`telecrypt-io storage` command group: login, recovery, shared vaults and nested folders, and file
upload, download, rename, and deletion. Its real-stack Harness scenarios exercise these same SDK
operations as the web UI; they are operator-local acceptance tests, never hosted CI.

**Distribution:** the standalone CLI is available only as an exact
[GitHub Release](https://github.com/TeleCrypt-io/storage-cli/releases), never from the NPM registry.

## Install

```bash
npm install -g https://github.com/TeleCrypt-io/storage-cli/releases/download/storage-cli-vX.Y.Z/storage-cli-vX.Y.Z.tgz
```

Replace `X.Y.Z` with an existing release version. `npm` is used only as the Node installer: the
archive and its bundled runtime dependencies are fetched from GitHub, not from the NPM registry.
This installs the `telecrypt-io` executable. The library source is in
[`TeleCrypt-io/storage-sdk`](https://github.com/TeleCrypt-io/storage-sdk).

## Quick start

```bash
telecrypt-io storage login --homeserver https://backend.telecrypt.io
telecrypt-io storage vault create Photos
telecrypt-io storage file upload <vaultId> ./cat.jpg
telecrypt-io storage vault share <vaultId> @bob:your.server --role editor
telecrypt-io storage recovery setup     # prints your Recovery Key — save it
```

The CLI supports MAS/OIDC device authorization only; it never sends a Matrix login password.

## Development

```bash
npm ci
# Start the shared disposable fixture from a Storage SDK checkout first.
npm test
```

The Storage SDK repository owns the local Synapse/MAS fixture. These tests connect to it at
`http://localhost:8008`; they never target a production server or duplicate the stack definition.

See [CLI.md](./CLI.md) for the full command reference and [RELEASING.md](./RELEASING.md) for the
guarded GitHub Release procedure.

## Licence

[Business Source License 1.1](./LICENSE). Non-commercial use is permitted; converts to
Apache License 2.0 on 2030-07-20.

For commercial licensing, contact TeleCrypt.io.

## Third-party code

- [`@telecrypt-io/storage`](https://www.npmjs.com/package/@telecrypt-io/storage) — TeleCrypt
  library dependency
