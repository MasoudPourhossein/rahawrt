#!/bin/sh
# Official x86 SDK test. Containers and host CA mounts are ephemeral.
set -eu
cd "$(dirname "$0")/.."
mode=${1:-full}
case "$mode" in full|leaf) ;; *) echo 'Usage: sh scripts/test-sdk.sh [full|leaf]' >&2; exit 1;; esac
sdk_image=openwrt/sdk@sha256:b28d5e4087dbd3f815a8bf5440a11e54e6bbd3d7400c3729d872e7940a4a77c1
sdk_name=rahawrt-sdk-24108-$$
sdk_root=$(pwd)
sdk_output="$sdk_root/.local/sdk-24.10.8-$mode"
mkdir -p "$sdk_output"
chmod 2770 "$sdk_output"
# Freeze exactly the source being tested; concurrent edits cannot change the
# expected payload while the SDK initializes its feeds.
python3 scripts/build.py > "$sdk_output/source-build.log"
cp dist/rahawrt-0.1.0.tar.gz "$sdk_output/source.tar.gz"
sdk_snapshot=$(mktemp -d "$sdk_root/.local/sdk-source.XXXXXX")
chmod 0755 "$sdk_snapshot"
tar -xzf "$sdk_output/source.tar.gz" -C "$sdk_snapshot"
sdk_started=0
sdk_cleanup() {
    if [ "$sdk_started" = 1 ]; then docker_local rm -f "$sdk_name" >/dev/null; fi
    rm -rf -- "$sdk_snapshot"
}
docker_local() {
    env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock "$@"
}
trap sdk_cleanup EXIT HUP INT TERM
docker_local info --format '{{.ServerVersion}}'
docker_local pull "$sdk_image"
# No host networking, privileged mode, session secrets or source writes.
docker_local run -d --name "$sdk_name" --group-add "$(id -g)" \
    --mount "type=bind,src=$sdk_snapshot,dst=/source,readonly" \
    --mount "type=bind,src=$sdk_output,dst=/result" \
    --mount type=bind,src=/etc/ssl/certs/ca-certificates.crt,dst=/run/trust/ca-certificates.crt,readonly \
    -e SSL_CERT_FILE=/run/trust/ca-certificates.crt \
    -e GIT_SSL_CAINFO=/run/trust/ca-certificates.crt \
    -e CURL_CA_BUNDLE=/run/trust/ca-certificates.crt \
    --entrypoint /bin/sh "$sdk_image" -c 'exec sleep infinity'
sdk_started=1
printf '%s\n' "$sdk_image" > "$sdk_output/image.txt"
# Remove only this helper's stale expected output before running a new check.
rm -f "$sdk_output/rahawrt_0.1.0-r1_all.ipk"
if ! docker_local exec "$sdk_name" /bin/sh /source/scripts/sdk-build-inside.sh "$mode" > "$sdk_output/build.log" 2>&1; then
    echo "SDK $mode build failed; inspect $sdk_output/build.log" >&2
    exit 1
fi
python3 scripts/verify-sdk-package.py "$sdk_output/rahawrt_0.1.0-r1_all.ipk" "$sdk_snapshot" "$sdk_output/verification.json"
printf '%s\n' "$mode" > "$sdk_output/verified-scope.txt"
echo "SDK $mode package verified; no router, emulator or dependency-scope claims beyond this mode."
