# `secure-storage` CLI

A terminal CLI over the `SecureStorage` library: log in, set up recovery, create shared
folders, invite participants, and upload/download end-to-end encrypted files — all driven
entirely by the library (this CLI does not reimplement crypto or Matrix logic).

See `STATUS.md` ("Phase 6") for how crypto state survives across the separate OS processes a
CLI necessarily runs as, and for the library-level bugs this work found and fixed.

## Setup

```sh
npm install
npm run build        # produces dist/cli/index.js
```

During development, run commands via `tsx` directly instead of building:

```sh
npx tsx src/cli/index.ts <command> [args] [--json]
```

Or, after `npm run build` / `npm link`, as the `secure-storage` binary.

## Profile / state

Every command reads/writes a **profile directory**: session (homeserver, userId, deviceId,
accessToken) and the crypto store snapshot. Default `~/.secure-storage`; override with
`SECURE_STORAGE_HOME` — this is how you run multiple independent accounts/devices side by side
(e.g. in tests, or to act as two participants on one machine):

```sh
SECURE_STORAGE_HOME=~/.secure-storage-alice secure-storage login --homeserver ... --user alice --password ...
SECURE_STORAGE_HOME=~/.secure-storage-bob   secure-storage login --homeserver ... --user bob   --password ...
```

## `--json`

Every command accepts `--json` (anywhere on the command line): machine-readable output on
stdout on success, or `{"error": "..."}` on stderr with a non-zero exit code on failure. Without
`--json`, commands print human-readable text instead. SDK-internal debug/warning logs are
suppressed by default; set `SECURE_STORAGE_DEBUG=1` to see them (routed to stderr, labelled).

## Commands

### Session

```sh
secure-storage login --homeserver <url> --user <localpart> --password <pw>
secure-storage register --homeserver <url> --user <localpart> --password <pw>   # dev/test convenience
secure-storage whoami
secure-storage logout
```

### Recovery (server-side key backup)

```sh
secure-storage recovery setup                  # prints the Recovery Key — save it, it's shown once
secure-storage recovery restore <recoveryKey>   # on a new device/profile, recovers previously uploaded files
```

### Folders

```sh
secure-storage folder create <name>
secure-storage folder list
secure-storage folder share <folderId> <userId> [--role viewer|editor]   # default: viewer
secure-storage folder join <folderId>            # accept a pending invite
secure-storage folder members <folderId>         # participants + roles
secure-storage folder unshare <folderId> <userId>
```

`folder share` can also be re-run against an existing participant to change their role.

### Files

```sh
secure-storage file upload <folderId> <path> [--name <name>]
secure-storage file list <folderId>
secure-storage file download <folderId> <fileId> <destPath>
```

## Example: two participants sharing a folder

```sh
export A=~/.secure-storage-alice
export B=~/.secure-storage-bob

SECURE_STORAGE_HOME=$A secure-storage register --homeserver http://localhost:8008 --user alice --password pw --json
SECURE_STORAGE_HOME=$B secure-storage register --homeserver http://localhost:8008 --user bob   --password pw --json

FOLDER_ID=$(SECURE_STORAGE_HOME=$A secure-storage folder create "Shared" --json | jq -r .folderId)

SECURE_STORAGE_HOME=$A secure-storage folder share "$FOLDER_ID" @bob:localhost --role editor --json
SECURE_STORAGE_HOME=$B secure-storage folder join "$FOLDER_ID" --json

SECURE_STORAGE_HOME=$B secure-storage file upload "$FOLDER_ID" ./report.pdf --json
# { "fileId": "$...", "name": "report.pdf" }

SECURE_STORAGE_HOME=$A secure-storage file list "$FOLDER_ID" --json
SECURE_STORAGE_HOME=$A secure-storage file download "$FOLDER_ID" '$...' ./report-downloaded.pdf --json
```

## Example: recovery on a new device

```sh
SECURE_STORAGE_HOME=$A secure-storage recovery setup --json
# { "recoveryKey": "EsTx ...." }  -- save this

# Later, on a fresh profile (new device, same account):
export A2=~/.secure-storage-alice-newlaptop
SECURE_STORAGE_HOME=$A2 secure-storage login --homeserver http://localhost:8008 --user alice --password pw --json
SECURE_STORAGE_HOME=$A2 secure-storage recovery restore "EsTx ...." --json
SECURE_STORAGE_HOME=$A2 secure-storage file download "$FOLDER_ID" '$...' ./recovered.pdf --json
```
