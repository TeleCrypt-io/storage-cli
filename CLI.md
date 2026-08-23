# `telecrypt-io` CLI

A terminal CLI over the `TeleCryptIOStorage` library: log in, set up recovery, create shared
vaults, invite participants, and upload/download end-to-end encrypted files — all driven
entirely by the library (this CLI does not reimplement crypto or Matrix logic). All commands live
under the `storage` namespace (`telecrypt-io storage ...`).

Crypto state is persisted in the selected profile so separate CLI processes can reopen the same
encrypted session.

## Setup

```sh
npm ci
```

During development, run commands via `tsx` directly instead of building:

```sh
npm exec -- tsx src/index.ts storage <command> [args] [--json]
```

## Profile / state

Every command reads/writes a **profile directory**: an OIDC session (homeserver, userId, deviceId,
access/refresh tokens) and the crypto store snapshot. Default `~/.telecrypt-io/storage`; override
with `TELECRYPT_IO_STORAGE_HOME` for independent accounts/devices. The profile directory and both
secret files must be owned by the current user, regular (not symlinked), and inaccessible to group
and other users; the CLI refuses unsafe state rather than trying to repair it.

```sh
TELECRYPT_IO_STORAGE_HOME=~/.telecrypt-io/storage-alice telecrypt-io storage login --homeserver https://backend.telecrypt.io
TELECRYPT_IO_STORAGE_HOME=~/.telecrypt-io/storage-bob   telecrypt-io storage login --homeserver https://backend.telecrypt.io
```

## `--json`

Every command accepts `--json` (anywhere on the command line): machine-readable output on
stdout on success, or `{"error": "..."}` on stderr with a non-zero exit code on failure. Without
`--json`, commands print human-readable text instead. SDK-internal debug/warning logs are
suppressed by default; set `TELECRYPT_IO_STORAGE_DEBUG=1` to see them (routed to stderr, labelled).

## Commands

### Session

```sh
telecrypt-io storage login --homeserver <url>
telecrypt-io storage whoami
telecrypt-io storage logout
```

### Recovery (server-side key backup)

```sh
telecrypt-io storage recovery setup                  # prints the Recovery Key — save it, it's shown once
telecrypt-io storage recovery restore                 # hidden Recovery Key prompt
printf '%s' "$RECOVERY_KEY" | telecrypt-io storage recovery restore --key-stdin
```

### Vaults

```sh
telecrypt-io storage vault create <name>
telecrypt-io storage vault list
telecrypt-io storage vault subfolder create <parentId> <name>
telecrypt-io storage vault subfolder list <parentId>
telecrypt-io storage vault subfolder rename <folderId> <name>
telecrypt-io storage vault subfolder delete <folderId>
telecrypt-io storage vault share <vaultId> <userId> [--role viewer|editor]   # default: viewer
telecrypt-io storage vault join <vaultId>            # accept a pending invite
telecrypt-io storage vault members <vaultId>         # participants + roles
telecrypt-io storage vault unshare <vaultId> <userId>
telecrypt-io storage vault rename <vaultId> <name>
telecrypt-io storage vault delete <vaultId>
```

`vault share` can also be re-run against an existing participant to change their role. The
`subfolder` commands manage nested directory nodes within a vault.

### Files

```sh
telecrypt-io storage file upload <treeId> <path> [--name <name>]
telecrypt-io storage file list <treeId>
telecrypt-io storage file download <treeId> <fileId> <destPath>
telecrypt-io storage file rename <treeId> <fileId> <name>
telecrypt-io storage file delete <treeId> <fileId>
```

## Example: two participants sharing a vault

```sh
export A=~/.telecrypt-io/storage-alice
export B=~/.telecrypt-io/storage-bob

TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage login --homeserver https://backend.telecrypt.io --json
TELECRYPT_IO_STORAGE_HOME=$B telecrypt-io storage login --homeserver https://backend.telecrypt.io --json

VAULT_ID=$(TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage vault create "Shared" --json | jq -r .id)

TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage vault share "$VAULT_ID" @bob:telecrypt.io --role editor --json
TELECRYPT_IO_STORAGE_HOME=$B telecrypt-io storage vault join "$VAULT_ID" --json

TELECRYPT_IO_STORAGE_HOME=$B telecrypt-io storage file upload "$VAULT_ID" ./report.pdf --json
# { "id": "$...", "name": "report.pdf", "mimetype": "application/pdf" }

TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage file list "$VAULT_ID" --json
TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage file download "$VAULT_ID" '$...' ./report-downloaded.pdf --json
```

## Example: recovery on a new device

```sh
TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage recovery setup --json
# { "recoveryKey": "EsTx ...." }  -- save this

# Later, on a fresh profile (new device, same account):
export A2=~/.telecrypt-io/storage-alice-newlaptop
TELECRYPT_IO_STORAGE_HOME=$A2 telecrypt-io storage login --homeserver https://backend.telecrypt.io --json
printf '%s' "$RECOVERY_KEY" | TELECRYPT_IO_STORAGE_HOME=$A2 telecrypt-io storage recovery restore --key-stdin --json
TELECRYPT_IO_STORAGE_HOME=$A2 telecrypt-io storage file download "$VAULT_ID" '$...' ./recovered.pdf --json
```
