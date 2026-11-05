#!/bin/sh
# Host integration fixture only: exact OpenWrt sources, no router/native payload.
set -eu
cd "$(dirname "$0")/.."
task_root=$(pwd)
task_prefix="$task_root/.local/uhttpd-tools"
mkdir -p .local/deps
for tool in cc pkg-config openssl git python3; do command -v "$tool" >/dev/null || { echo "Missing host build tool: $tool" >&2; exit 1; }; done
checkout_source() {
    task_name=$1; task_url=$2; task_revision=$3
    if [ ! -e ".local/deps/$task_name" ]; then
        git clone --filter=blob:none --no-checkout "$task_url" ".local/deps/$task_name"
        git -C ".local/deps/$task_name" fetch --depth 1 origin "$task_revision"
        git -C ".local/deps/$task_name" checkout --detach "$task_revision"
    fi
    [ "$(git -C ".local/deps/$task_name" rev-parse HEAD)" = "$task_revision" ] || { echo "Unexpected $task_name revision; inspect the existing cache." >&2; exit 1; }
    [ -z "$(git -C ".local/deps/$task_name" status --porcelain)" ] || { echo "Preserve and inspect modified $task_name sources before rebuilding." >&2; exit 1; }
}
checkout_source libubox https://github.com/openwrt/libubox.git 49056d178f42da98048a5d4c23f83a6f6bc6dd80
checkout_source ustream-ssl https://github.com/openwrt/ustream-ssl.git 99bd3d2b167ccdffb6de072d02c380cb37b23e33
checkout_source uhttpd https://github.com/openwrt/uhttpd.git 7e64e8bad2415cec0a6d9770ec379db54273c7a7
task_cmake="$task_root/.local/cmake-tools/cmake/data/bin/cmake"
if [ ! -x "$task_cmake" ]; then python3 -m pip install --target .local/cmake-tools cmake==3.31.10; fi
"$task_cmake" --version | head -1 | awk '$3=="3.31.10" {ok=1} END {exit !ok}'
if ! pkg-config --exists json-c; then
    if [ ! -f .local/tools/usr/lib/x86_64-linux-gnu/pkgconfig/json-c.pc ]; then
        [ "$(uname -m)" = x86_64 ] && [ -r /usr/share/keyrings/debian-archive-keyring.gpg ] || { echo 'Install native json-c development headers first.' >&2; exit 1; }
        mkdir -p .local/apt/lists/partial .local/apt/debs .local/tools
        printf '%s\n' 'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] https://deb.debian.org/debian trixie main' > .local/apt/uhttpd-sources.list
        apt_local() {
            apt-get -o Dir::Etc::parts=- -o "Dir::Etc::sourcelist=$task_root/.local/apt/uhttpd-sources.list" -o Dir::Etc::sourceparts=- -o "Dir::State::Lists=$task_root/.local/apt/lists" "$@"
        }
        apt_local update
        (cd .local/apt/debs && apt_local download libjson-c-dev libjson-c5)
        for file in .local/apt/debs/libjson-c*.deb; do dpkg-deb -x "$file" .local/tools; done
    fi
    export PKG_CONFIG_PATH="$task_root/.local/tools/usr/lib/x86_64-linux-gnu/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    export PKG_CONFIG_SYSROOT_DIR="$task_root/.local/tools"
fi
"$task_cmake" -S .local/deps/libubox -B .local/libubox-build -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF -DUNIT_TESTING=OFF -DCMAKE_INSTALL_PREFIX="$task_prefix" -DCMAKE_PREFIX_PATH="$task_root/.local/tools/usr" -DCMAKE_LIBRARY_PATH="$task_root/.local/tools/usr/lib/x86_64-linux-gnu"
"$task_cmake" --build .local/libubox-build -j 2
"$task_cmake" --install .local/libubox-build
"$task_cmake" -S .local/deps/ustream-ssl -B .local/ustream-build -DCMAKE_PREFIX_PATH="$task_prefix" -DCMAKE_INSTALL_PREFIX="$task_prefix"
"$task_cmake" --build .local/ustream-build -j 2
"$task_cmake" --install .local/ustream-build
"$task_cmake" -S .local/deps/uhttpd -B .local/uhttpd-build -DLUA_SUPPORT=OFF -DUBUS_SUPPORT=OFF -DUCODE_SUPPORT=OFF -DTLS_SUPPORT=ON -DCMAKE_PREFIX_PATH="$task_prefix;$task_root/.local/tools/usr" -DCMAKE_LIBRARY_PATH="$task_root/.local/tools/usr/lib/x86_64-linux-gnu" -DCMAKE_INSTALL_PREFIX="$task_prefix"
"$task_cmake" --build .local/uhttpd-build -j 2
"$task_cmake" --install .local/uhttpd-build
