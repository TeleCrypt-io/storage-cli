#!/usr/bin/env bash
set -euo pipefail

fixture_root="${HARNESS_ARTIFACTS_ROOT:-${TMPDIR:-/tmp}}"
repo=$(mktemp -d "$fixture_root/storage-cli-transport.XXXXXX")
printf 'retained synthetic repository: %s\n' "$repo"

export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_SYSTEM=/dev/null
export GIT_CONFIG_COUNT=0
export GIT_CONFIG_PARAMETERS=
export GIT_TERMINAL_PROMPT=0

git -C "$repo" init -q
git -C "$repo" remote add origin https://evil.invalid/storage-cli.git
git -C "$repo" config --local url.evil.insteadOf https://github.com/
git -C "$repo" config --local url.evil.pushInsteadOf https://github.com/
git -C "$repo" config --local include.path /tmp/untrusted-git-config
included_config="$repo/included.gitconfig"
printf '%s\n' '[http]' 'sslVerify = false' 'extraHeader = Authorization: Basic evil' > "$included_config"
git -C "$repo" config --local "includeIf.gitdir:${repo}/.git.path" "$included_config"
git -C "$repo" config --local credential.helper evil-helper
git -C "$repo" config --local http.proxy http://evil.invalid
git -C "$repo" config --local http.sslVerify false
git -C "$repo" config --local http.sslCAInfo /tmp/evil-ca
git -C "$repo" config --local http.extraHeader 'Authorization: Basic evil'
git -C "$repo" config --local http.cookiefile /tmp/evil-cookie
git -C "$repo" config --local http.saveCookies true
git -C "$repo" config --local remote.origin.uploadpack evil-upload-pack
git -C "$repo" config --local remote.origin.receivepack evil-receive-pack
git -C "$repo" config --local remote.origin.pushurl https://evil.invalid/push.git
git -C "$repo" config --local remote.origin.vcs evil-vcs
git -C "$repo" config --local core.gitProxy evil-proxy
git -C "$repo" config --local core.sshCommand evil-ssh

bash scripts/hardenReleaseTransport.sh "$repo" https://github.com/TeleCrypt-io/storage-cli.git
test "$(git -C "$repo" remote get-url origin)" = https://github.com/TeleCrypt-io/storage-cli.git
test "$(git -C "$repo" remote get-url --push origin)" = https://github.com/TeleCrypt-io/storage-cli.git
if git -C "$repo" config --local --no-includes --get-regexp \
  '^(include(if)?(\..+)?\.path|url\.|credential\.|(http|https)\..*(proxy|sslverify|sslcainfo|sslcapath|sslcert|sslkey|sslcertpasswordprotected|extraheader|cookiefile|savecookies)|remote\..*(proxy|uploadpack|receivepack|pushurl|vcs)|core\.(gitproxy|sshcommand))'; then
  echo "unsafe local Git configuration survived transport hardening" >&2
  exit 1
fi
if git -C "$repo" config --get-regexp '^(http|https)\..*(proxy|sslverify|sslcainfo|extraheader)$'; then
  echo "unsafe included Git configuration remained active" >&2
  exit 1
fi
