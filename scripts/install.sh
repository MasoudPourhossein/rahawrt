#!/bin/sh
# Local, signed OpenWrt .ipk/.apk installation. Never executes downloaded scripts.
set -eu
[ "$(id -u)" = 0 ] || { echo 'Run as root on OpenWrt.' >&2; exit 1; }
[ -f /etc/openwrt_release ] || { echo 'OpenWrt required.' >&2; exit 1; }
[ "$#" = 4 ] || { echo 'Usage: sh install.sh PACKAGE SIGNED_MANIFEST SIGNATURE TRUSTED_USIGN_PUBLIC_KEY' >&2; exit 1; }
pkg=$1
manifest=$2
signature=$3
key=$4
case "$pkg" in *.ipk|*.apk) ;; *) echo 'Only OpenWrt packages accepted.' >&2; exit 1;; esac
command -v uci >/dev/null || { echo 'OpenWrt UCI is required.' >&2; exit 1; }
[ -x /etc/init.d/passwall2 ] && uci -q show passwall2 >/dev/null || { echo 'Install and configure PassWall2 first; RahaWRT does not install it.' >&2; exit 1; }
for tool in usign sha256sum awk df; do command -v "$tool" >/dev/null || { echo "Missing dependency: $tool" >&2; exit 1; }; done
# A release manifest is generated only after exact SDK builds are tested.
# Lines: release VERSION ARCH ; checksum SHA256 BASENAME
release=$(uci -q get system.@system[0].hostname || echo OpenWrt)
. /etc/openwrt_release
if command -v opkg >/dev/null; then
    manager=opkg
    arches=$(opkg print-architecture | awk '$2!="all" && $2!="noarch" {print $2}')
elif command -v apk >/dev/null; then
    manager=apk
    arches=$(apk --print-arch)
else
    echo 'No supported package manager.' >&2; exit 1
fi
case "$manager:$pkg" in opkg:*.ipk|apk:*.apk) ;; *) echo 'Package format does not match this OpenWrt package manager.' >&2; exit 1;; esac
[ -n "${DISTRIB_ARCH:-}" ] || { echo 'OpenWrt package architecture is missing.' >&2; exit 1; }
printf '%s\n' "$arches" | awk -v arch="$DISTRIB_ARCH" '$0==arch {ok=1} END {exit !ok}' || { echo 'Release and package-manager architecture disagree.' >&2; exit 1; }
arches=$DISTRIB_ARCH
memory=$(awk '$1=="MemTotal:" {print $2}' /proc/meminfo)
[ "${memory:-0}" -ge 131072 ] || { echo 'At least 128 MiB RAM required for this development version.' >&2; exit 1; }
usign -V -p "$key" -m "$manifest" -x "$signature"
found=0
for arch in $arches; do
    if awk -v ver="$DISTRIB_RELEASE" -v arch="$arch" '$1=="release" && $2==ver && $3==arch { ok=1 } END { exit !ok }' "$manifest"; then found=1; fi
done
[ "$found" = 1 ] || { echo 'No signed support entry for this exact release/architecture.' >&2; exit 1; }
name=$(basename "$pkg")
expected=$(awk -v name="$name" '$1=="checksum" && $3==name {print $2}' "$manifest")
[ "${#expected}" = 64 ] || { echo 'Missing or ambiguous package checksum.' >&2; exit 1; }
actual=$(sha256sum "$pkg" | awk '{print $1}')
[ "$actual" = "$expected" ] || { echo 'Package checksum mismatch.' >&2; exit 1; }
free=$(df -Pk /overlay 2>/dev/null | awk 'END {print $4}')
[ "${free:-0}" -ge 65536 ] || { echo 'At least 64 MiB free overlay required (Python runtime and state).' >&2; exit 1; }
printf 'Installing for OpenWrt %s on %s (%s).\n' "$DISTRIB_RELEASE" "$release" "$manager"
# Dependencies must be available in trusted, signed native feeds.
if [ "$manager" = opkg ]; then opkg install "$pkg"; else apk add "$pkg"; fi
echo 'Installed, not activated. Create admin, review policy, then explicitly enable service.'
