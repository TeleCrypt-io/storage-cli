# `telecrypt-io` CLI

A terminal CLI over the `TeleCryptIOStorage` library: log in, set up recovery, create shared
folders, invite participants, and upload/download end-to-end encrypted files — all driven
entirely by the library (this CLI does not reimplement crypto or Matrix logic). All storage
commands live under the `storage` namespace (`telecrypt-io storage ...`), leaving room for other
TeleCrypt.io command groups to be added under the same `telecrypt-io` binary later.

See `STATUS.md` ("Phase 6") for how crypto state survives across the separate OS processes a
CLI necessarily runs as, and for the library-level bugs this work found and fixed.

## Setup

```sh
npm install
npm run build        # produces dist/cli/index.js
```

During development, run commands via `tsx` directly instead of building:

```sh
npx tsx src/cli/index.ts storage <command> [args] [--json]
```

Or, after `npm run build` / `npm link`, as the `telecrypt-io` binary.

## Profile / state

Every command reads/writes a **profile directory**: session (homeserver, userId, deviceId,
accessToken) and the crypto store snapshot. Default `~/.telecrypt-io/storage`; override with
`TELECRYPT_IO_STORAGE_HOME` — this is how you run multiple independent accounts/devices side by
side (e.g. in tests, or to act as two participants on one machine):

```sh
TELECRYPT_IO_STORAGE_HOME=~/.telecrypt-io/storage-alice telecrypt-io storage login --homeserver ... --user alice --password ...
TELECRYPT_IO_STORAGE_HOME=~/.telecrypt-io/storage-bob   telecrypt-io storage login --homeserver ... --user bob   --password ...
```

## `--json`

Every command accepts `--json` (anywhere on the command line): machine-readable output on
stdout on success, or `{"error": "..."}` on stderr with a non-zero exit code on failure. Without
`--json`, commands print human-readable text instead. SDK-internal debug/warning logs are
suppressed by default; set `TELECRYPT_IO_STORAGE_DEBUG=1` to see them (routed to stderr, labelled).

## Commands

### Session

```sh
telecrypt-io storage login --homeserver <url> --user <localpart> --password <pw>
telecrypt-io storage register --homeserver <url> --user <localpart> --password <pw>   # dev/test convenience
telecrypt-io storage whoami
telecrypt-io storage logout
```

### Recovery (server-side key backup)

```sh
telecrypt-io storage recovery setup                  # prints the Recovery Key — save it, it's shown once
telecrypt-io storage recovery restore <recoveryKey>   # on a new device/profile, recovers previously uploaded files
```

### Folders

```sh
telecrypt-io storage folder create <name>
telecrypt-io storage folder list
telecrypt-io storage folder share <folderId> <userId> [--role viewer|editor]   # default: viewer
telecrypt-io storage folder join <folderId>            # accept a pending invite
telecrypt-io storage folder members <folderId>         # participants + roles
telecrypt-io storage folder unshare <folderId> <userId>
```

`folder share` can also be re-run against an existing participant to change their role.

### Files

```sh
telecrypt-io storage file upload <folderId> <path> [--name <name>]
telecrypt-io storage file list <folderId>
telecrypt-io storage file download <folderId> <fileId> <destPath>
```

## Example: two participants sharing a folder

```sh
export A=~/.telecrypt-io/storage-alice
export B=~/.telecrypt-io/storage-bob

TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage register --homeserver http://localhost:8008 --user alice --password pw --json
TELECRYPT_IO_STORAGE_HOME=$B telecrypt-io storage register --homeserver http://localhost:8008 --user bob   --password pw --json

FOLDER_ID=$(TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage folder create "Shared" --json | jq -r .folderId)

TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage folder share "$FOLDER_ID" @bob:localhost --role editor --json
TELECRYPT_IO_STORAGE_HOME=$B telecrypt-io storage folder join "$FOLDER_ID" --json

TELECRYPT_IO_STORAGE_HOME=$B telecrypt-io storage file upload "$FOLDER_ID" ./report.pdf --json
# { "fileId": "$...", "name": "report.pdf" }

TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage file list "$FOLDER_ID" --json
TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage file download "$FOLDER_ID" '$...' ./report-downloaded.pdf --json
```

## Example: recovery on a new device

```sh
TELECRYPT_IO_STORAGE_HOME=$A telecrypt-io storage recovery setup --json
# { "recoveryKey": "EsTx ...." }  -- save this

# Later, on a fresh profile (new device, same account):
export A2=~/.telecrypt-io/storage-alice-newlaptop
TELECRYPT_IO_STORAGE_HOME=$A2 telecrypt-io storage login --homeserver http://localhost:8008 --user alice --password pw --json
TELECRYPT_IO_STORAGE_HOME=$A2 telecrypt-io storage recovery restore "EsTx ...." --json
TELECRYPT_IO_STORAGE_HOME=$A2 telecrypt-io storage file download "$FOLDER_ID" '$...' ./recovered.pdf --json
```
