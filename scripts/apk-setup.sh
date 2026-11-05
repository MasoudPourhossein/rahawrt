#!/bin/sh
# Build dependency cache only; never changes an OpenWrt checkout or router.
set -eu
cd "$(dirname "$0")/.."
task_root=$(pwd)
task_commit=b5a31c0d865342ad80be10d68f1bb3d3ad9b0866
mkdir -p .local/deps
if [ ! -e .local/deps/apk-tools ]; then
    git clone --filter=blob:none --no-checkout https://github.com/alpinelinux/apk-tools.git .local/deps/apk-tools
    git -C .local/deps/apk-tools fetch --depth 1 origin "$task_commit"
    git -C .local/deps/apk-tools checkout --detach "$task_commit"
fi
[ "$(git -C .local/deps/apk-tools rev-parse HEAD)" = "$task_commit" ] || { echo 'Unexpected APK tool revision; preserve and inspect this cache before replacing it.' >&2; exit 1; }
git -C .local/deps/apk-tools diff --exit-code
python3 -m pip install --target .local/meson-tools meson==1.9.2 ninja==1.13.0
export PYTHONPATH="$task_root/.local/meson-tools"
export PATH="$task_root/.local/meson-tools/bin:$PATH"
if [ ! -f .local/apk-build/build.ninja ]; then
    VERSION=3.0.5 python3 -m mesonbuild.mesonmain setup .local/apk-build .local/deps/apk-tools -Ddocs=disabled -Dhelp=disabled -Dtests=disabled -Dcrypto_backend=openssl -Durl_backend=wget -Dzstd=disabled -Dpython=disabled -Dlua=disabled -Ddefault_library=static
fi
python3 -m mesonbuild.mesonmain compile -C .local/apk-build -j 2
.local/apk-build/src/apk --version
