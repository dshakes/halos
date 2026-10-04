#!/usr/bin/env bash
# Browser e2e against a running `make demo` (make demo-e2e): headless Chromium
# walks both self-service journeys (web/e2e/1-journeys.spec.ts) and then clicks
# through every console page and button (2-clickthrough.spec.ts), failing on any
# visible error or console error. The developer journey runs the kiosk's laptop
# command in a throwaway container on the demo network and asserts the kiosk
# then shows that device enrolled and compliant; the admin journey asserts every
# page's empty and populated states, approvals opening a PR, and the audit chain.
# Kiosk pages are also checked at phone width. Screenshots land in web/e2e-results/out.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${HALO_DEMO_CONSOLE_PORT:=18080}" "${HALO_DEMO_DL_PORT:=18082}"
export HALO_DEMO_CONSOLE_PORT HALO_DEMO_DL_PORT
out=${HALO_E2E_OUT:-$PWD/web/e2e-results/out}
mkdir -p "$out"

(cd web && { [ -d node_modules ] || npm ci --no-audit --no-fund; } &&
  npx playwright install ${PLAYWRIGHT_DEPS:+--with-deps} chromium &&
  HALO_E2E_URL="http://localhost:$HALO_DEMO_CONSOLE_PORT" HALO_E2E_OUT="$out" npx playwright test)
echo "demo-e2e: both journeys pass; the kiosk's laptop command enrolled halod, which pulled and verified its ring's signed release and the kiosk showed it compliant. Screenshots: $out"
