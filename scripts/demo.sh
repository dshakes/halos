#!/usr/bin/env bash
# One-command playground: the whole Halos stack on Docker with a seeded policy
# repo, mock OIDC login and mock model upstreams. DEV ONLY.
#   scripts/demo.sh        bring it up and print the URLs   (make demo)
#   scripts/demo.sh down   stop it and delete its volumes   (make demo-down)
# Ports: HALO_DEMO_{CONSOLE,IDP,PROXY,SHADOW_METRICS}_PORT, HALO_OBS_GRAFANA_PORT.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${HALO_DEMO_CONSOLE_PORT:=18080}" "${HALO_DEMO_IDP_PORT:=18081}" "${HALO_DEMO_PROXY_PORT:=18088}"
: "${HALO_DEMO_SHADOW_METRICS_PORT:=18090}" "${HALO_OBS_GRAFANA_PORT:=13000}"
export HALO_DEMO_CONSOLE_PORT HALO_DEMO_IDP_PORT HALO_DEMO_PROXY_PORT HALO_DEMO_SHADOW_METRICS_PORT HALO_OBS_GRAFANA_PORT
# Browser-facing URLs. In a Codespace the browser reaches forwarded ports at
# https://<codespace>-<port>.<domain>, not localhost, so the OIDC round trip uses those.
url() { # port
  if [ -n "${CODESPACE_NAME:-}" ] && [ -n "${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-}" ]; then
    echo "https://$CODESPACE_NAME-$1.$GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN"
  else
    echo "http://localhost:$1"
  fi
}
: "${HALO_DEMO_CONSOLE_URL:=$(url "$HALO_DEMO_CONSOLE_PORT")}" "${HALO_DEMO_IDP_URL:=$(url "$HALO_DEMO_IDP_PORT")}"
export HALO_DEMO_CONSOLE_URL HALO_DEMO_IDP_URL
# Generated collector config (gitignored); the included obs compose bind-mounts it.
export HALO_OTELCOL_CONFIG="$PWD/deploy/compose/demo/.otelcol.yaml"
dc() { docker compose -f deploy/compose/docker-compose.demo.yml "$@"; }

if [ "${1:-up}" = down ]; then
  dc down -v --remove-orphans
  rm -f "$HALO_OTELCOL_CONFIG"
  exit 0
fi

dc build
# Collector config from the real CLI, in the halo image (no host Go needed).
dc run --rm --no-deps -T --entrypoint /usr/local/bin/app seed \
  telemetry collector-config --clickhouse tcp://clickhouse:9000 >"$HALO_OTELCOL_CONFIG"
dc up -d

wait_for() { # name url [status]: default any 2xx; halo-proxy answers 401 without a token
  for _ in $(seq 120); do
    if [ -n "${3:-}" ]; then
      [ "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$2")" = "$3" ] && return 0
    else
      curl -fsS -o /dev/null "$2" 2>/dev/null && return 0
    fi
    sleep 1
  done
  echo "demo: $1 not healthy at $2; see: docker compose -f deploy/compose/docker-compose.demo.yml logs $1" >&2
  exit 1
}
wait_for halo-server "http://localhost:$HALO_DEMO_CONSOLE_PORT/healthz"
wait_for mock-idp "http://localhost:$HALO_DEMO_IDP_PORT/.well-known/openid-configuration"
wait_for halo-shadow "http://localhost:$HALO_DEMO_SHADOW_METRICS_PORT/metrics"
wait_for grafana "http://localhost:$HALO_OBS_GRAFANA_PORT/api/health"
wait_for halo-proxy "http://localhost:$HALO_DEMO_PROXY_PORT/v1/messages" 401

cat <<EOF

Halos demo is up (DEV ONLY: mock IdP, mock models, throwaway keys).

  What                      URL
  Console + portal          $HALO_DEMO_CONSOLE_URL   (Sign in -> pick a demo user)
  Mock IdP (OIDC)           $HALO_DEMO_IDP_URL/.well-known/openid-configuration
  halo-proxy (model API)    http://localhost:$HALO_DEMO_PROXY_PORT/v1/messages
  halo-shadow metrics       http://localhost:$HALO_DEMO_SHADOW_METRICS_PORT/metrics
  Grafana                   http://localhost:$HALO_OBS_GRAFANA_PORT   (admin / halo-dev-only)

  Demo user            Groups        Ring / role
  alice@acme.com       ai-platform   ring0-harness-team, admin (sees experiments, rollouts, toggles)
  bob@acme.com         eng           ring2-early (claude-cli A/B, sonnet shadow)
  mallory@acme.com     eng           ring1-canary (opus-5-5 canary)
  dave@acme.com        eng           ring3-ga

  Call the proxy as alice:
    TOK=\$(curl -s 'localhost:$HALO_DEMO_IDP_PORT/token?user=alice@acme.com&groups=ai-platform')
    curl -s localhost:$HALO_DEMO_PROXY_PORT/v1/messages -H "Authorization: Bearer \$TOK" \\
      -H 'content-type: application/json' -H 'anthropic-version: 2023-06-01' \\
      -d '{"model":"sonnet","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}'

  Tear down: make demo-down
EOF
