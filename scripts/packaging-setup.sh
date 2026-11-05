#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .local
package_tool=.local/openwrt-ipkg-build
package_hash=60714afe9b93fd0d3ecfd2fcef7839928b1a99e826ae30e2e3c0e24f1efde474
if [ ! -e "$package_tool" ]; then
    curl --fail --location --max-time 30 https://raw.githubusercontent.com/openwrt/openwrt/34fa4b1af5a30d3a789f07078b91e23e78dad622/scripts/ipkg-build -o "$package_tool.download"
    printf '%s  %s\n' "$package_hash" "$package_tool.download" | sha256sum -c -
    mv "$package_tool.download" "$package_tool"
fi
printf '%s  %s\n' "$package_hash" "$package_tool" | sha256sum -c -
sh scripts/apk-setup.sh
