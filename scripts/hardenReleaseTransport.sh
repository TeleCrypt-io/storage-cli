#!/usr/bin/env bash
set -euo pipefail

repo_dir=${1:?repository directory is required}
expected_remote=${2:?canonical repository URL is required}

git_dir=$(git -C "$repo_dir" rev-parse --git-dir)
test -n "$git_dir"

read_matching_keys() {
  local pattern=$1
  local -n output=$2
  local status

  # `git config --get-regexp` returns 1 when no key matches. Every other
  # failure is real and must retain the command's complete diagnostics.
  if output="$(git -C "$repo_dir" config --local --no-includes --name-only --get-regexp "$pattern")"; then
    status=0
  else
    status="$?"
  fi
  if test "$status" != 0 && test "$status" != 1; then
    if test -n "$output"; then printf '%s\n' "$output" >&2; fi
    return "$status"
  fi
  if test "$status" = 1; then output=; fi
}

remove_keys() {
  local pattern=$1
  local key keys
  read_matching_keys "$pattern" keys
  while IFS= read -r key; do
    test -n "$key" || continue
    git -C "$repo_dir" config --local --no-includes --unset-all "$key"
  done <<< "$keys"
}

unsafe_config_pattern='^(include(if)?(\..+)?\.path|url\..*\.(insteadOf|pushInsteadOf)|credential\..*|(http|https)\..*(proxy|sslverify|sslcainfo|sslcapath|sslcert|sslkey|sslcertpasswordprotected|extraheader|cookiefile|savecookies)|remote\..*\.(proxy|uploadpack|receivepack|pushurl|vcs)|core\.(gitproxy|sshcommand))$'

# Only the checkout's local config is mutable at this point. Remove settings
# that could redirect Git, load another config file, or supply credentials.
remove_keys '^include(if)?(\..+)?\.path$'
remove_keys '^url\..*\.insteadOf$'
remove_keys '^url\..*\.pushInsteadOf$'
remove_keys '^credential\..*'
remove_keys '^(http|https)\..*(proxy|sslverify|sslcainfo|sslcapath|sslcert|sslkey|sslcertpasswordprotected|extraheader|cookiefile|savecookies)$'
remove_keys '^remote\..*\.(proxy|uploadpack|receivepack|pushurl)$'
remove_keys '^remote\..*\.vcs$'
remove_keys '^core\.(gitproxy|sshcommand)$'

# Replace every local fetch URL atomically so a duplicate URL cannot survive
# and be used by a later Git operation. A conditional include that adds another
# URL is rejected by the exact one-URL checks below.
git -C "$repo_dir" config --local --no-includes --replace-all remote.origin.url "$expected_remote"

test "$(git -C "$repo_dir" remote get-url --all origin | wc -l)" = 1
test "$(git -C "$repo_dir" remote get-url --all origin)" = "$expected_remote"
test "$(git -C "$repo_dir" remote get-url --push --all origin | wc -l)" = 1
test "$(git -C "$repo_dir" remote get-url --push --all origin)" = "$expected_remote"

remaining=
read_matching_keys "$unsafe_config_pattern" remaining
if test -n "$remaining"; then
  printf 'unsafe local Git configuration remains: %s\n' "$remaining" >&2
  exit 1
fi
