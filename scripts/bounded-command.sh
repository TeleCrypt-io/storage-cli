#!/usr/bin/env bash
set -euo pipefail

max_stdout="${1:?maximum stdout bytes are required}"
max_stderr="${2:?maximum stderr bytes are required}"
stdout_path="${3:?stdout path is required}"
stderr_path="${4:?stderr path is required}"
timeout_seconds="${5:?timeout seconds are required}"
shift 5
[[ "$max_stdout" =~ ^[1-9][0-9]*$ && "$max_stderr" =~ ^[1-9][0-9]*$ ]] || exit 64
[[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]] || exit 64
[[ $# -gt 0 ]] || exit 64

temporary="$(mktemp -d)"
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT
trap 'cleanup; exit 143' HUP INT TERM
set +e
/usr/bin/python3 "$(dirname -- "${BASH_SOURCE[0]}")/bounded-command.py" \
  --stdout-limit "$max_stdout" --stderr-limit "$max_stderr" \
  --stdout-path "$temporary/stdout" --stderr-path "$temporary/stderr" \
  --timeout "$timeout_seconds" -- "$@"
status=$?
set -e
cp -- "$temporary/stdout" "$stdout_path"
cp -- "$temporary/stderr" "$stderr_path"
exit "$status"
