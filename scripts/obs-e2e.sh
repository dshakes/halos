#!/usr/bin/env bash
# Evidence-plane e2e: brings up deploy/observability (otel-collector-contrib,
# ClickHouse, Grafana), sends synthetic harness telemetry, and asserts rows,
# `halo exp analyze` verdicts and Grafana panels (test/e2e/obs_test.go).
# Then the closed loop (test/e2e/obs_loop_test.go): real traffic through
# halo-proxy -> ClickHouse -> halo-server --controller -> signed kill -> proxy.
# Needs Docker + network (image pulls, Grafana plugin download). Extra args go to `go test`.
set -euo pipefail
cd "$(dirname "$0")/.."
t0=$SECONDS

export COMPOSE_PROJECT_NAME="halo-obs-e2e-$$"
# Free loopback ports unless the caller pins them (avoids clashing with other stacks).
free_port() { python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'; }
export HALO_OBS_CH_HTTP_PORT="${HALO_OBS_CH_HTTP_PORT:-$(free_port)}"
export HALO_OBS_OTLP_HTTP_PORT="${HALO_OBS_OTLP_HTTP_PORT:-$(free_port)}"
export HALO_OBS_OTLP_GRPC_PORT="${HALO_OBS_OTLP_GRPC_PORT:-$(free_port)}"
export HALO_OBS_OTLP_GATEWAY_PORT="${HALO_OBS_OTLP_GATEWAY_PORT:-$(free_port)}"
export HALO_OBS_OTLP_EVAL_PORT="${HALO_OBS_OTLP_EVAL_PORT:-$(free_port)}"
export HALO_OBS_GRAFANA_PORT="${HALO_OBS_GRAFANA_PORT:-$(free_port)}"
export HALO_OBS_E2E=1

work=$(mktemp -d)
export HALO_OTELCOL_CONFIG="$work/otelcol.yaml"
compose() { docker compose -f deploy/observability/docker-compose.yml "$@"; }
cleanup() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

go run ./cmd/halo telemetry collector-config --clickhouse tcp://clickhouse:9000 --eval-receiver -o "$HALO_OTELCOL_CONFIG" >/dev/null
# Fail fast on a config the collector cannot load.
docker run --rm -e CLICKHOUSE_USER=x -e CLICKHOUSE_PASSWORD=x -e HALO_OTLP_GATEWAY_TOKEN=x -e HALO_OTLP_EVAL_TOKEN=x -v "$HALO_OTELCOL_CONFIG:/c.yaml:ro" \
  "$(sed -n 's/^ *image: \(otel\/[^ ]*\)$/\1/p' deploy/observability/docker-compose.yml)" validate --config=/c.yaml

compose up -d
echo "obs-e2e: waiting for Grafana (plugin install + provisioning)"
for _ in $(seq 120); do
  curl -fsS "http://127.0.0.1:$HALO_OBS_GRAFANA_PORT/api/health" >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS "http://127.0.0.1:$HALO_OBS_GRAFANA_PORT/api/health" >/dev/null || { compose logs >&2; echo "obs-e2e: stack never became healthy" >&2; exit 1; }
echo "obs-e2e: stack up after $((SECONDS - t0))s"

rc=0
go test -tags e2e ./test/e2e/ -run TestObs -v -count=1 -timeout 10m "$@" || rc=$?
[ "$rc" = 0 ] || compose logs --tail=80 otel-collector grafana >&2
echo "obs-e2e: total $((SECONDS - t0))s (exit $rc)"
exit "$rc"
