#!/usr/bin/env bash
set -euo pipefail

repo_dir=${1:?repository directory is required}
expected_remote=${2:?canonical repository URL is required}

git_dir=$(git -C "$repo_dir" rev-parse --git-dir)
test -n "$git_dir"

remove_keys() {
  local pattern=$1
  local key
  while IFS= read -r key; do
    test -n "$key" || continue
    git -C "$repo_dir" config --local --no-includes --unset-all "$key"
  done < <(git -C "$repo_dir" config --local --no-includes --name-only --get-regexp "$pattern" || true)
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

# Replace every local fetch URL so a duplicate URL cannot survive and be used
# by a later Git operation. A conditional include that adds another URL is
# rejected by the exact one-URL checks below.
git -C "$repo_dir" config --local --no-includes --unset-all remote.origin.url || true
git -C "$repo_dir" remote set-url origin "$expected_remote"

test "$(git -C "$repo_dir" remote get-url --all origin | wc -l)" = 1
test "$(git -C "$repo_dir" remote get-url --all origin)" = "$expected_remote"
test "$(git -C "$repo_dir" remote get-url --push --all origin | wc -l)" = 1
test "$(git -C "$repo_dir" remote get-url --push --all origin)" = "$expected_remote"

remaining=$(git -C "$repo_dir" config --local --no-includes --name-only --get-regexp \
  "$unsafe_config_pattern" || true)
if test -n "$remaining"; then
  printf 'unsafe local Git configuration remains: %s\n' "$remaining" >&2
  exit 1
fi
