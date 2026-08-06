# TeleCrypt.io Storage CLI

The command-line interface for TeleCrypt.io end-to-end encrypted Matrix storage.

It consumes one exact public `@telecrypt-io/storage` library version and provides the
`telecrypt-io storage` command group: login, recovery, shared folders and subfolders, and file
upload, download, rename, and deletion. Its real-stack Harness scenarios exercise these same SDK
operations as the web UI; they are operator-local acceptance tests, never hosted CI.

**Distribution:** the standalone CLI is available only as an exact
[GitHub Release](https://github.com/TeleCrypt-io/storage-cli/releases), never from the NPM
registry. The existing combined `@telecrypt-io/storage@0.1.3` package remains unchanged.

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
telecrypt-io storage login --homeserver https://your.server
telecrypt-io storage folder create Photos
telecrypt-io storage file upload <folderId> ./cat.jpg
telecrypt-io storage folder share <folderId> @bob:your.server --role editor
telecrypt-io storage recovery setup     # prints your Recovery Key — save it
```

`login` always uses the OAuth/OIDC device-code flow: open the displayed URL,
enter the displayed code, and approve it in your browser. It never accepts a
password. Session and crypto state live in `~/.telecrypt-io/storage` by
default; set `TELECRYPT_IO_STORAGE_HOME` to use a separate profile.

Recovery Keys are secrets. `recovery restore` prompts without echoing the key;
for automation, send it on standard input instead of putting it in command
history, process listings, or argv:

```bash
printf '%s\n' "$RECOVERY_KEY" | telecrypt-io storage recovery restore --recovery-key-stdin
```

Every command accepts `--json` anywhere in its invocation, for example
`telecrypt-io storage folder list --json` or `telecrypt-io --json storage folder list`.

## Development

```bash
npm install
npm run synapse:up     # disposable local Synapse for tests
npm test
npm run synapse:down
```

Tests run against a real local Synapse in podman, never against a production server.

See [CLI.md](./CLI.md) for the full command reference and [RELEASING.md](./RELEASING.md) for the
guarded GitHub Release procedure.

## Licence

[Business Source License 1.1](./LICENSE). Non-commercial use is permitted; converts to
Apache License 2.0 on 2030-07-20.

For commercial licensing, contact TeleCrypt.io.

## Third-party code

- [`@telecrypt-io/storage`](https://www.npmjs.com/package/@telecrypt-io/storage) — TeleCrypt
  library dependency
