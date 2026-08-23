# `telecrypt-io` CLI

A terminal CLI over the `TeleCryptIOStorage` library: log in, set up recovery, create shared
folders, invite participants, and upload/download end-to-end encrypted files — all driven
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

### Folders

```sh
telecrypt-io storage folder create <name>
telecrypt-io storage folder list
telecrypt-io storage folder subfolder create <folderId> <name>
telecrypt-io storage folder subfolder list <folderId>
telecrypt-io storage folder share <folderId> <userId> [--role viewer|editor]   # default: viewer
telecrypt-io storage folder join <folderId>            # accept a pending invite
telecrypt-io storage folder members <folderId>         # participants + roles
telecrypt-io storage folder unshare <folderId> <userId>
telecrypt-io storage folder rename <folderId> <name>
telecrypt-io storage folder delete <folderId>
```

`folder share` can also be re-run against an existing participant to change their role.

### Files

```sh
telecrypt-io storage file upload <folderId> <path> [--name <name>]
telecrypt-io storage file list <folderId>
telecrypt-io storage file download <folderId> <fileId> <destPath>
telecrypt-io storage file rename <folderId> <fileId> <name>
telecrypt-io storage file delete <folderId> <fileId>
```

## Example: two participants sharing a folder

```sh
export A=~/.telecrypt-io/storage-alice
export B=~/.telecrypt-io/storage-bob

TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage login --homeserver https://backend.telecrypt.io --json
TELECRYPT_IO_STORAGE_HOME=$B telecrypt-io storage login --homeserver https://backend.telecrypt.io --json

FOLDER_ID=$(TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage folder create "Shared" --json | jq -r .id)

TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage folder share "$FOLDER_ID" @bob:telecrypt.io --role editor --json
TELECRYPT_IO_STORAGE_HOME=$B telecrypt-io storage folder join "$FOLDER_ID" --json

TELECRYPT_IO_STORAGE_HOME=$B telecrypt-io storage file upload "$FOLDER_ID" ./report.pdf --json
# { "id": "$...", "name": "report.pdf", "mimetype": "application/pdf" }

TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage file list "$FOLDER_ID" --json
TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage file download "$FOLDER_ID" '$...' ./report-downloaded.pdf --json
```

## Example: recovery on a new device

```sh
TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage recovery setup --json
# { "recoveryKey": "EsTx ...." }  -- save this

# Later, on a fresh profile (new device, same account):
export A2=~/.telecrypt-io/storage-alice-newlaptop
TELECRYPT_IO_STORAGE_HOME=$A2 telecrypt-io storage login --homeserver https://backend.telecrypt.io --json
printf '%s' "$RECOVERY_KEY" | TELECRYPT_IO_STORAGE_HOME=$A2 telecrypt-io storage recovery restore --key-stdin --json
TELECRYPT_IO_STORAGE_HOME=$A2 telecrypt-io storage file download "$FOLDER_ID" '$...' ./recovered.pdf --json
```
