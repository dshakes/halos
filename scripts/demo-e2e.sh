#!/usr/bin/env bash
# Browser e2e against a running `make demo` (make demo-e2e): headless Chromium
# clicks through every console page and button and fails on any visible error
# or console error (web/e2e), then runs the kiosk's laptop command in a
# throwaway container on the demo network and proves the enrolled halod pulls
# and verifies its ring's signed release.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${HALO_DEMO_CONSOLE_PORT:=18080}" "${HALO_DEMO_DL_PORT:=18082}"
out=${HALO_E2E_OUT:-$PWD/web/e2e-results/out}
mkdir -p "$out"
rm -f "$out/laptop.sh"

(cd web && { [ -d node_modules ] || npm ci --no-audit --no-fund; } &&
  npx playwright install ${PLAYWRIGHT_DEPS:+--with-deps} chromium &&
  HALO_E2E_URL="http://localhost:$HALO_DEMO_CONSOLE_PORT" HALO_E2E_OUT="$out" npx playwright test)

# The command is generated for this laptop (localhost URLs); inside the container
# socat maps those ports to the services, and registry:5000 resolves on the network.
cmd=$(cat "$out/laptop.sh")
docker run --rm --network halos-demo_default -e CMD="$cmd" alpine:3.20 sh -euc "
  apk add -q --no-cache curl socat >/dev/null
  socat TCP-LISTEN:$HALO_DEMO_CONSOLE_PORT,fork,reuseaddr TCP:halo-server:8080 &
  socat TCP-LISTEN:$HALO_DEMO_DL_PORT,fork,reuseaddr TCP:downloads:8080 &
  sleep 1
  sh -c \"\$CMD\"
  /usr/local/lib/halos/halod once --install=false
  /usr/local/lib/halos/halod status"
echo "demo-e2e: console click-through clean; the kiosk's laptop command enrolled halod, which pulled and verified its ring's signed release"
