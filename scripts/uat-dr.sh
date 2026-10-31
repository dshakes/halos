#!/usr/bin/env bash
# Disaster-recovery drill for the HA control plane on Postgres (guides/backup-and-restore):
#   write state through the API -> pg_dump -> write more -> destroy the database -> restore -> assert.
# What it proves: everything written before the dump comes back (kill list, audit hash chain), nothing after it does (that
# window is the RPO of a logical dump), both replicas serve and exactly one controller leads again, and writes work afterwards.
#
#   make uat-dr               # kind: the chart with HA values on a throwaway kind cluster (halos-dr)
#   scripts/uat-dr.sh local   # no Kubernetes: docker Postgres + two halo-server processes (same assertions)
#   UAT_KEEP=1 ...            # keep the cluster / container afterwards
#
# kind mode only ever touches the kind-halos-dr context. Needs docker, jq, curl, openssl, go; kind mode also kind, kubectl,
# helm, git. Test only: it runs halo-server with --dev-insecure-user (no login) and plain-TCP Postgres.
set -euo pipefail
cd "$(dirname "$0")/.."
MODE=${1:-kind}
case "$MODE" in kind | local) ;; *) echo "usage: $0 [kind|local]" >&2; exit 2 ;; esac

CLUSTER=halos-dr
CTX=kind-$CLUSTER
NS=halos-dr
PGC=halos-dr-pg                  # local mode: the Postgres container
PGPASS=$(openssl rand -hex 12)
t0=$SECONDS
need=(docker jq curl openssl go)
[ "$MODE" = kind ] && need+=(kind kubectl helm git)
for tool in "${need[@]}"; do command -v "$tool" >/dev/null || { echo "uat-dr: $tool not found" >&2; exit 1; }; done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/halos-dr.XXXXXX")
PIDS=()
K=(kubectl --context "$CTX")
H=(helm --kube-context "$CTX")

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  rc=$?
  for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
  if [ "$rc" != 0 ] && [ "$MODE" = kind ] && kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    echo "uat-dr: failed (exit $rc); pod state:" >&2
    "${K[@]}" -n "$NS" get pods -o wide >&2 || true
    "${K[@]}" -n $NS logs deploy/halos-server --tail=40 >&2 || true
  fi
  if [ "${UAT_KEEP:-0}" = 1 ]; then
    echo "uat-dr: keeping $([ "$MODE" = kind ] && echo "cluster $CLUSTER" || echo "container $PGC") and $WORK (UAT_KEEP=1)"
  else
    if [ "$MODE" = kind ]; then kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; else docker rm -f $PGC >/dev/null 2>&1 || true; fi
    rm -rf "$WORK"
  fi
  echo "uat-dr: total $((SECONDS - t0))s"
}
trap cleanup EXIT

fails=0
check() { # name, ok(0|1), evidence
  if [ "$2" = 0 ]; then echo "  [PASS] $1: $3"; else echo "  [FAIL] $1: $3"; fails=$((fails + 1)); fi
}
retry() { # seconds, command...: until it succeeds
  local n=$1; shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}

# ---- binaries ----
ARCH=$(docker version --format '{{.Server.Arch}}')
mkdir -p "$WORK/bin" "$WORK/ctx/linux/$ARCH" "$WORK/keys"
echo "uat-dr: building binaries"
go build -o "$WORK/bin/halo" ./cmd/halo
HALO=$WORK/bin/halo
if [ "$MODE" = local ]; then
  go build -o "$WORK/bin/halo-server" ./cmd/halo-server
else
  CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -ldflags "-s -w -X main.version=dr" -o "$WORK/ctx/linux/$ARCH/halo-server" ./cmd/halo-server
fi
"$HALO" keys generate --name killswitch --out "$WORK/keys" >/dev/null
openssl rand -hex 32 > "$WORK/gateway.token"
openssl rand -hex 32 > "$WORK/fleet.token"

# ---- environment: one implementation per mode of the same small interface ----
#   env_up        Postgres + policy repo reachable, schema migrated, URL file for the host in $WORK/dburl
#   servers_up    start the (two) halo-server replicas and wait until they are ready
#   servers_down  stop them
#   pg_sql SQL    run SQL as the database owner against the maintenance database
#   pg_dump_to F  logical dump of the halos database into F
#   pg_restore_from F
#   replicas_ready / leaders           health, as the operator sees them
API=""
if [ "$MODE" = local ]; then
  PGPORT_HOST=${UAT_DR_PGPORT:-55432}
  DB_URL="postgres://halos:$PGPASS@127.0.0.1:$PGPORT_HOST/halos?sslmode=disable"
  env_up() {
    docker rm -f $PGC >/dev/null 2>&1 || true
    docker run -d --name $PGC -e POSTGRES_USER=halos -e POSTGRES_PASSWORD="$PGPASS" -e POSTGRES_DB=halos \
      -p "127.0.0.1:$PGPORT_HOST:5432" postgres:16-alpine >/dev/null
    retry 60 docker exec $PGC pg_isready -U halos -d halos || { echo "uat-dr: postgres never became ready" >&2; exit 1; }
    sleep 2   # the image restarts the server once after its init scripts
    retry 30 docker exec $PGC pg_isready -U halos -d halos
    printf '%s\n' "$DB_URL" > "$WORK/dburl"
    "$WORK/bin/halo-server" migrate --database-url-file "$WORK/dburl" >/dev/null
    API=http://127.0.0.1:18081
  }
  SRV_ARGS=(--policy-dir examples/acme-corp --token-file "$WORK/fleet.token" --dev-insecure-user dr --dev-insecure-admin
    --database-url-file "$WORK/dburl" --killswitch-key-file "$WORK/keys/killswitch.key" --gateway-token-file "$WORK/gateway.token"
    --controller --clickhouse-url http://127.0.0.1:1 --leader-lease-ttl 3s)
  servers_up() {
    PIDS=()
    for i in 1 2; do
      "$WORK/bin/halo-server" "${SRV_ARGS[@]}" --listen "127.0.0.1:1808$i" --metrics-listen "127.0.0.1:1809$i" >> "$WORK/server-$i.log" 2>&1 &
      PIDS+=("$!")
    done
    for i in 1 2; do retry 60 curl -fsS --max-time 5 "http://127.0.0.1:1808$i/readyz" || { echo "uat-dr: replica $i never became ready" >&2; tail -20 "$WORK/server-$i.log" >&2; exit 1; }; done
  }
  servers_down() {
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && { wait "$p" 2>/dev/null || true; }; done
    PIDS=()
  }
  pg_sql() { docker exec $PGC psql -U halos -d postgres -v ON_ERROR_STOP=1 -tAc "$1"; }
  pg_dump_to() { docker exec $PGC pg_dump -U halos --format=custom halos > "$1"; }
  pg_restore_from() { docker exec -i $PGC pg_restore -U halos --no-owner --exit-on-error -d halos < "$1"; }
  replicas_ready() { n=0; for i in 1 2; do curl -fsS --max-time 5 "http://127.0.0.1:1808$i/readyz" >/dev/null 2>&1 && n=$((n + 1)); done; echo $n; }
  leaders() { n=0; for i in 1 2; do curl -fsS "http://127.0.0.1:1809$i/metrics" | grep -q '^halo_leader{lease="controller"} 1$' && n=$((n + 1)); done; echo $n; }
else
  PGPORT_HOST=15432
  DB_URL="postgres://halos:$PGPASS@postgres.$NS.svc.cluster.local:5432/halos?sslmode=disable"
  kn() { "${K[@]}" -n $NS "$@"; }
  env_up() {
    kind get clusters 2>/dev/null | grep -qx "$CLUSTER" && { echo "uat-dr: cluster $CLUSTER already exists (delete it first)" >&2; exit 1; }
    kind create cluster --name "$CLUSTER" --image "${UAT_KIND_IMAGE:-kindest/node:v1.32.2}" --wait 180s
    echo "uat-dr: building and loading images"
    mkdir -p "$WORK/ctx/linux/$ARCH"
    docker build -q -f deploy/docker/Dockerfile.service --build-arg BINARY=halo-server -t ghcr.io/dshakes/halo-server:dr "$WORK/ctx" >/dev/null
    docker build -q -t halos-dr/git:dr test/uat/dr >/dev/null
    EXT=(postgres:16-alpine registry.k8s.io/git-sync/git-sync:v4.4.0)
    for i in "${EXT[@]}"; do docker image inspect "$i" >/dev/null 2>&1 || docker pull -q "$i" >/dev/null; done
    # single-platform archive: `kind load docker-image` fails on multi-arch images from Docker's containerd store
    docker save --platform "linux/$ARCH" -o "$WORK/images.tar" ghcr.io/dshakes/halo-server:dr halos-dr/git:dr "${EXT[@]}" 2>/dev/null ||
      docker save -o "$WORK/images.tar" ghcr.io/dshakes/halo-server:dr halos-dr/git:dr "${EXT[@]}"
    kind load image-archive --name "$CLUSTER" "$WORK/images.tar" >/dev/null
    rm -f "$WORK/images.tar"

    "${K[@]}" create namespace $NS >/dev/null
    sec() { kn create secret generic "$@" >/dev/null; }
    sec halos-pg --from-literal=POSTGRES_USER=halos --from-literal=POSTGRES_PASSWORD="$PGPASS" --from-literal=POSTGRES_DB=halos
    sec halos-postgres --from-literal=url="$DB_URL"
    sec halos-fleet-token --from-file=token="$WORK/fleet.token"
    sec halos-session --from-literal=session-key="$(openssl rand -hex 32)"
    sec halos-killswitch --from-file=signing-key="$WORK/keys/killswitch.key" --from-file=gateway-token="$WORK/gateway.token"
    "${K[@]}" apply -f test/uat/dr/infra.yaml >/dev/null
    for d in git postgres; do kn rollout status deploy/$d --timeout 180s >/dev/null; done

    # policy repo: examples/acme-corp pushed to the in-cluster git daemon
    cp -R examples/acme-corp "$WORK/policy"
    git -C "$WORK/policy" init -q -b main
    git -C "$WORK/policy" -c user.name=dr -c user.email=dr@halos.invalid add -A
    git -C "$WORK/policy" -c user.name=dr -c user.email=dr@halos.invalid commit -qm "acme-corp"
    "${K[@]}" -n "$NS" port-forward svc/git 19418:9418 >/dev/null 2>&1 & PIDS+=("$!")
    retry 30 git ls-remote git://127.0.0.1:19418/policy.git || { echo "uat-dr: git daemon not reachable" >&2; exit 1; }
    git -C "$WORK/policy" push -q git://127.0.0.1:19418/policy.git main

    echo "uat-dr: helm install (HA values: 2 replicas on Postgres, migrate hook Job)"
    "${H[@]}" upgrade --install halos deploy/helm/halos -n $NS -f test/uat/dr/values-dr.yaml --wait --timeout 6m
    # host-side URL for `halo audit verify` (loopback, so sslmode=disable is accepted)
    "${K[@]}" -n "$NS" port-forward svc/postgres "$PGPORT_HOST:5432" >/dev/null 2>&1 & PIDS+=("$!")
    printf 'postgres://halos:%s@127.0.0.1:%s/halos?sslmode=disable\n' "$PGPASS" "$PGPORT_HOST" > "$WORK/dburl"
    API=http://127.0.0.1:18080
    api_forward
  }
  api_forward() {
    if [ -n "${API_PF:-}" ]; then kill "$API_PF" 2>/dev/null || true; wait "$API_PF" 2>/dev/null || true; fi   # free 18080 first
    "${K[@]}" -n "$NS" port-forward svc/halos-server 18080:80 >/dev/null 2>&1 & API_PF=$!; PIDS+=("$API_PF")
    retry 60 curl -fsS --max-time 5 "$API/readyz" || { echo "uat-dr: server not reachable through the port-forward" >&2; exit 1; }
  }
  servers_up() {
    kn scale deploy/halos-server --replicas 2 >/dev/null
    kn rollout status deploy/halos-server --timeout 240s >/dev/null
    api_forward
  }
  servers_down() {
    kn scale deploy/halos-server --replicas 0 >/dev/null
    retry 120 sh -c "[ -z \"\$(kubectl --context $CTX -n $NS get pods -l app.kubernetes.io/component=server -o name)\" ]"
  }
  pg_sql() { kn exec deploy/postgres -- psql -U halos -d postgres -v ON_ERROR_STOP=1 -tAc "$1"; }
  pg_dump_to() { kn exec deploy/postgres -- pg_dump -U halos --format=custom halos > "$1"; }
  pg_restore_from() { kn exec -i deploy/postgres -- pg_restore -U halos --no-owner --exit-on-error -d halos < "$1"; }
  replicas_ready() { kn get deploy/halos-server -o jsonpath='{.status.readyReplicas}' | sed 's/^$/0/'; }
  leaders() {
    n=0
    for pod in $(kn get pods -l app.kubernetes.io/component=server -o jsonpath='{.items[*].metadata.name}'); do
      "${K[@]}" get --raw "/api/v1/namespaces/$NS/pods/$pod:9092/proxy/metrics" 2>/dev/null | grep -q '^halo_leader{lease="controller"} 1$' && n=$((n + 1))
    done
    echo $n
  }
fi

# ---- API helpers (--dev-insecure-user acts as an admin) ----
api() { curl -fsS --max-time 15 -H 'Content-Type: application/json' "$@"; }
kill_item() { # kind(toggles|experiments) name reason -> prints the HTTP status
  curl -s --max-time 15 -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d "{\"reason\":\"$3\"}" "$API/api/v1/$1/$2/kill"
}
killed_names() { api "$API/api/v1/killswitch" | jq -r '.killed[] | select(.killed) | .experiment' | sort | tr '\n' ' '; }
audit_total() { api "$API/api/v1/audit?limit=1" | jq -r '"\(.total) \(.head) \(.verified)"'; }

# ---- the drill ----
echo "uat-dr: [$MODE] bringing up the environment"
env_up
servers_up 2>/dev/null || true
retry 90 test "$(replicas_ready)" = 2 || { echo "uat-dr: replicas never became 2/2 ready" >&2; exit 1; }

echo "uat-dr: 1. write state through the API"
check "kill a toggle" "$([ "$(kill_item toggles sonnet-next-route "dr drill: first")" = 200 ] && echo 0 || echo 1)" "POST /api/v1/toggles/sonnet-next-route/kill"
check "kill an experiment" "$([ "$(kill_item experiments opus-5-5-canary "dr drill: second")" = 200 ] && echo 0 || echo 1)" "POST /api/v1/experiments/opus-5-5-canary/kill"
want_names=$(killed_names)
read -r want_total want_head want_verified <<< "$(audit_total)"
check "state present before the backup" "$([ "$want_names" = "opus-5-5-canary toggle:sonnet-next-route " ] && [ "$want_verified" = true ] && echo 0 || echo 1)" "killed [$want_names], audit $want_total entries, verified=$want_verified"

echo "uat-dr: 2. pg_dump (online, one repeatable-read snapshot)"
pg_dump_to "$WORK/halos.dump"
size=$(wc -c < "$WORK/halos.dump" | tr -d ' ')
check "dump written" "$([ "$size" -gt 1000 ] && echo 0 || echo 1)" "$size bytes"

check "a write after the backup" "$([ "$(kill_item toggles format-hook "dr drill: after the dump")" = 200 ] && echo 0 || echo 1)" "kill format-hook (this is the data a restore from this dump loses)"

echo "uat-dr: 3. disaster: stop the servers, drop the database"
servers_down
pg_sql "DROP DATABASE halos WITH (FORCE)" >/dev/null
pg_sql "CREATE DATABASE halos" >/dev/null
tables=$(docker_tables=$(pg_sql "SELECT 1" >/dev/null && echo ok); [ "$docker_tables" = ok ] && echo 0)
check "database destroyed and recreated empty" "$([ "$tables" = 0 ] && echo 0 || echo 1)" "DROP/CREATE DATABASE halos"

echo "uat-dr: 4. restore (servers stay down)"
pg_restore_from "$WORK/halos.dump"
servers_up
retry 120 test "$(replicas_ready)" = 2 || true

echo "uat-dr: 5. assert"
check "both replicas ready again" "$([ "$(replicas_ready)" = 2 ] && echo 0 || echo 1)" "/readyz on 2 of 2 replicas"
got_names=$(killed_names)
check "kill list restored to the backup" "$([ "$got_names" = "$want_names" ] && echo 0 || echo 1)" "killed [$got_names] (want [$want_names]; format-hook, written after the dump, is gone)"
read -r got_total got_head got_verified <<< "$(audit_total)"
check "audit chain identical to the backup point" "$([ "$got_total $got_head $got_verified" = "$want_total $want_head $want_verified" ] && echo 0 || echo 1)" "$got_total entries, head ${got_head:0:12}, verified=$got_verified"
v=0; "$HALO" audit verify --database-url-file "$WORK/dburl" > "$WORK/verify.txt" 2>&1 || v=$?
check "halo audit verify against the restored database" "$v" "exit $v: $(head -1 "$WORK/verify.txt")"
retry 60 test "$(leaders)" = 1 || true
check "exactly one controller leader" "$([ "$(leaders)" = 1 ] && echo 0 || echo 1)" "halo_leader{lease=\"controller\"} = 1 on $(leaders) replica(s)"
gw=$(curl -s --max-time 15 -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(cat "$WORK/gateway.token")" "$API/api/v1/gateway/killswitch")
check "gateways can poll the signed kill list" "$([ "$gw" = 200 ] && echo 0 || echo 1)" "GET /api/v1/gateway/killswitch -> $gw"
check "writes work after the restore" "$([ "$(kill_item toggles format-hook "dr drill: re-issued after restore")" = 200 ] && echo 0 || echo 1)" "re-issued the kill the restore lost"
read -r _ _ again_verified <<< "$(audit_total)"
check "audit chain still linear after new writes" "$([ "$again_verified" = true ] && echo 0 || echo 1)" "verified=$again_verified"

if [ "$fails" != 0 ]; then echo "uat-dr: $fails check(s) failed" >&2; exit 1; fi
echo "uat-dr: all checks passed"
