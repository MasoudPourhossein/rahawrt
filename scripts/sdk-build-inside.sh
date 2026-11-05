#!/bin/sh
# Runs only inside the pinned official SDK container; /source is read-only.
set -eu
umask 022
[ -f /builder/rules.mk ] && [ -d /builder/staging_dir/toolchain-x86_64_gcc-13.3.0_musl ] || { echo 'Expected OpenWrt 24.10.8 x86_64 SDK.' >&2; exit 1; }
mode=${1:-full}
case "$mode" in full|leaf) ;; *) echo 'Expected full or leaf build mode.' >&2; exit 1;; esac
cd /builder
cat > feeds.conf <<'EOF'
src-git base https://github.com/openwrt/openwrt.git;v24.10.8
src-git packages https://github.com/openwrt/packages.git^23abaa6f3b0fdfd76b570031107e5718476ff0c8
src-git luci https://github.com/openwrt/luci.git^cac97ed67cfbcad90db49f5f3b1245c2c4cbfae5
src-git passwall_packages https://github.com/Openwrt-Passwall/openwrt-passwall-packages.git^da712cf06cf4e6fd39e147fb36e6ec936003fcc9
src-git passwall2 https://github.com/Openwrt-Passwall/openwrt-passwall2.git^176e27cb8d9852ce9b30d2e180810b544d8fc9dc
EOF
./scripts/feeds update -a
./scripts/feeds install -a
mkdir -p package/rahawrt
tar -C /source -cf - Makefile openwrt rahawrt web LICENSE THIRD_PARTY.md scripts | tar -xf - -C package/rahawrt
printf '%s\n' 'CONFIG_PACKAGE_rahawrt=m' >> .config
make defconfig
if [ "$mode" = full ]; then
    make package/rahawrt/compile V=s -j2
else
    # This validates the SDK package recipe/payload only. It does not rebuild
    # dependencies and must never be labeled a full dependency build.
    export PATH=/builder/staging_dir/host/bin:$PATH
    make -C package/rahawrt TOPDIR=/builder compile V=s -j2
fi
find bin -name '*rahawrt*.*pk' -exec cp '{}' /result/ \;
find /result -name '*rahawrt*.*pk' -exec sha256sum '{}' \;
