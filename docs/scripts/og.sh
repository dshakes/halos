#!/usr/bin/env bash
# Renders docs/public/og.svg (from assets/src/build.py) to the 1200x630 social card docs/public/og.png.
set -euo pipefail
cd "$(dirname "$0")/../public"
chrome=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
"$chrome" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
  --window-size=1200,630 --screenshot="$PWD/og.tmp.png" "file://$PWD/og.svg" >/dev/null 2>&1 &
pid=$!; for _ in $(seq 60); do [ -s og.tmp.png ] && break; sleep 0.5; done; sleep 0.5; kill $pid 2>/dev/null || true
mv og.tmp.png og.png  # a stale og.png must not satisfy the wait above
file og.png
