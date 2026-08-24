# `telecrypt-io` CLI

A terminal CLI over the `TeleCryptIOStorage` library: log in, set up recovery, create shared
vaults, invite participants, and upload/download end-to-end encrypted files — all driven
entirely by the library (this CLI does not reimplement crypto or Matrix logic). All commands live
under the `storage` namespace (`telecrypt-io storage ...`).

Crypto state is persisted in the selected profile so separate CLI processes can reopen the same
encrypted session. `TELECRYPT_IO_STORAGE_HOME`, when set, must be an existing or creatable
canonical absolute path (no relative paths, `.`/`..` components, or trailing separator).

The CLI requires Linux with `/proc/self/fd` and Node.js `>=22.23.2`. Release verification
uses that exact Node.js version and the bundled npm `10.9.8`.

## Setup

```sh
npm ci --ignore-scripts
```

During development, run commands via `tsx` directly instead of building:

```sh
npm exec --ignore-scripts -- tsx src/index.ts storage <command> [args] [--json]
```

## Profile / state

Every command reads/writes a **profile directory**: an OIDC session (homeserver, userId, deviceId,
issuer and token metadata, access/refresh tokens) and the crypto store snapshot. Default `~/.telecrypt-io/storage`; override
with `TELECRYPT_IO_STORAGE_HOME` for independent accounts/devices. When set, that variable must be
a canonical absolute path without relative or trailing components. The profile directory and its
private state files must be owned by the current user, regular (not symlinked), and inaccessible to group
and other users; the CLI refuses unsafe state rather than trying to repair it.
Commands hold an exclusive profile lock for their full lifetime, so refresh, logout, and crypto
snapshot writes cannot race or resurrect an older session. A failed local cleanup after a successful
remote logout leaves a private retry marker; rerunning logout completes cleanup without reusing the
revoked token.
The persisted device ID is required and is passed back into the shared refresh adapter, binding every
refreshed OAuth scope to the Matrix device that owns this profile; a missing device identity is rejected
before storage opens.
Issuer and token endpoint metadata are also required and are checked against the trusted homeserver and
issuer path before refresh or logout. Profiles written by older CLI releases without the issuer binding
are rejected and must be logged in again; the CLI never guesses missing OIDC authority.
These checks protect against other users and accidental symlink/path substitution; as with ordinary
private same-UID application state, a same-user process with write access to the profile directory is
inside the trust boundary. The retained directory handle, no-follow reads, atomic writes, and full-command
lock prevent pathname replacement from moving an active command to a different profile. The profile is
protected by filesystem ownership and mode checks; bearer tokens and cryptographic state are not wrapped
in an additional application-level at-rest encryption layer. Every command requires Linux
`/proc/self/fd` so profile and file paths can remain anchored without a native `openat` wrapper.

```sh
TELECRYPT_IO_STORAGE_HOME="$HOME/.telecrypt-io/storage-alice" telecrypt-io storage login --homeserver https://backend.telecrypt.io
TELECRYPT_IO_STORAGE_HOME="$HOME/.telecrypt-io/storage-bob"   telecrypt-io storage login --homeserver https://backend.telecrypt.io
```

## `--json`

Every command accepts `--json` (anywhere on the command line): machine-readable output on
stdout on success, or `{"error": "..."}` on stderr with a non-zero exit code on failure. Without
`--json`, commands print human-readable text instead. SDK-internal diagnostic logs are suppressed
so they cannot corrupt either output stream.

## Commands

### Session

```sh
telecrypt-io storage login --homeserver <url>
telecrypt-io storage login --homeserver <url> --no-browser
telecrypt-io storage whoami
telecrypt-io storage logout
```

Login opens the verification page through the system browser by default. Use `--no-browser` on
headless or remotely operated machines; the verification URL and code are still printed.

Logout revokes the server session before removing local credentials. If the server cannot be
reached or rejects the request, the profile is retained so logout can be retried.

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

Delete files before deleting their containing folder or vault. Folder and vault deletion refuses
nonempty trees, including child folders; remove empty child folders explicitly first.

File inputs and outputs are limited to 128 MiB. The CLI reads upload inputs through an anchored
descriptor and rejects same-size mutation detected during the read; downloads use an atomic temporary
file and refuse every existing destination, including regular files. Download bytes are held in memory,
bounded to 128 MiB, and kept inside the command's 120-second cancellation boundary before atomic install.

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
