#!/bin/sh
# Debian development helper. Downloads verified packages into an ignored local cache.
set -eu
cd "$(dirname "$0")/.."
python3 -c 'import sqlite3, ssl, hashlib; assert hasattr(hashlib, "pbkdf2_hmac")'
if command -v nft >/dev/null 2>&1; then exit 0; fi
[ "$(uname -m)" = x86_64 ] || { echo 'Install native nftables for kernel tests on this host architecture.' >&2; exit 1; }
root=$(pwd)
mkdir -p .local/apt/lists/partial .local/apt/cache/archives/partial .local/apt/debs .local/tools
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian trixie main' > .local/apt/sources.list
apt_local() {
    apt-get -o Dir::Etc::parts=- -o "Dir::Etc::sourcelist=$root/.local/apt/sources.list" -o Dir::Etc::sourceparts=- -o "Dir::State::Lists=$root/.local/apt/lists" -o "Dir::Cache=$root/.local/apt/cache" -o Acquire::Retries=0 "$@"
}
apt_local update
(cd .local/apt/debs && apt_local download nftables libnftables1)
for file in .local/apt/debs/*.deb; do dpkg-deb -x "$file" .local/tools; done
