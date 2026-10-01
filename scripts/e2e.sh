#!/usr/bin/env bash
# Cross-component e2e suite (test/e2e, build tag e2e): real halo/halod/halo-proxy/
# halo-shadow/halo-server binaries against registry:2, a mock OIDC issuer and mock
# LLM upstreams. Needs Docker unless HALO_E2E_REGISTRY=host:port is set.
# Extra args go to `go test` (e.g. -run TestGateway).
set -euo pipefail
cd "$(dirname "$0")/.."

# Sweep anything the suite (or an interrupted run) left behind; TestMain also
# removes its own registry container.
sweep() {
  local ids
  ids=$(docker ps -aq --filter label=halos-e2e=1 2>/dev/null || true)
  [ -z "$ids" ] || docker rm -f $ids >/dev/null 2>&1 || true
  ids=$(docker network ls -q --filter label=halos-e2e=1 2>/dev/null || true)
  [ -z "$ids" ] || docker network rm $ids >/dev/null 2>&1 || true
}
if [ -z "${HALO_E2E_REGISTRY:-}" ]; then trap sweep EXIT INT TERM; fi

go test -tags e2e ./test/e2e/... -v -count=1 -timeout 20m "$@"
