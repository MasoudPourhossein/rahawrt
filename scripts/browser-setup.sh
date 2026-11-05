#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
npm install --prefix .local/browser --no-save --package-lock=false playwright@1.64.1
if [ "${RAHAWRT_CHROMIUM:-}" = bundled ] || ! command -v chromium >/dev/null 2>&1; then
    .local/browser/node_modules/.bin/playwright install chromium
fi
