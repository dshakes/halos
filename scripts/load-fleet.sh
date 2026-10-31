#!/usr/bin/env bash
# Fleet-scale load test for halo-server: N simulated halod devices enroll, poll
# the ring pointer, post status reports and fetch the signed kill list, with
# the server in file mode (--data-dir) and/or Postgres mode (--database-url-file).
# Report: $OUT/<mode>-<devices>x<scale>/report.{md,json} and $OUT/summary.md.
#
#   make load-fleet                                   # 1000 5000 10000 devices, file + Postgres (Docker)
#   LOAD_FLEET_SCENARIOS="1000x1" make load-fleet     # smoke
#   LOAD_FLEET_SCENARIOS="5000x10" make load-fleet    # 10x the real request rate from 5000 devices
#
# Environment:
#   LOAD_FLEET_SCENARIOS  space-separated <devices>x<scale>      (default: 1000x1 5000x1 10000x1)
#   LOAD_FLEET_MODES      file and/or pg                         (default: file pg; pg is skipped without Docker)
#   LOAD_FLEET_DATABASE_URL  use this Postgres (CI service container) instead of starting one in Docker;
#                         each scenario starts from an empty public schema (needs psql)
#   LOAD_FLEET_ARGS       extra flags for the generator (-ramp 60s -duration 120s -operators 2 -conn-per-device ...)
#   LOAD_FLEET_OUT        output directory                       (default: load-fleet-out)
#   LOAD_FLEET_GOMAXPROCS cap the server's GOMAXPROCS (model a pod CPU limit; default: unset)
#   LOAD_FLEET_PGPORT     host port of the Docker Postgres       (default: 55433)
#   LOAD_FLEET_SERVER_BIN use this halo-server binary instead of the one built from the tree
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

SCENARIOS=${LOAD_FLEET_SCENARIOS:-1000x1 5000x1 10000x1}
MODES=${LOAD_FLEET_MODES:-file pg}
OUT=${LOAD_FLEET_OUT:-load-fleet-out}
PGPORT=${LOAD_FLEET_PGPORT:-55433}
PGC=halos-load-fleet-pg
# A free local port: nothing accepts a connection on it (a busy shared machine may hold the usual ones).
free_port() {
  local p
  while :; do
    p=$((20000 + RANDOM % 20000))
    (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null || { echo "$p"; return; }
  done
}
LISTEN=127.0.0.1:${LOAD_FLEET_PORT:-$(free_port)}
METRICS=127.0.0.1:$(free_port)
EXTRA=(${LOAD_FLEET_ARGS:-})
case $OUT in /*) ;; *) OUT=$ROOT/$OUT ;; esac

WORK=$(mktemp -d "${TMPDIR:-/tmp}/load-fleet.XXXXXX")
SRV_PID=""
cleanup() {
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true
  docker rm -f "$PGC" >/dev/null 2>&1 || true
  /bin/rm -rf "$WORK"
}
trap cleanup EXIT

# Many simulated devices hold many sockets.
ulimit -n "$(ulimit -Hn | sed 's/unlimited/65536/')" 2>/dev/null || ulimit -n 10240 2>/dev/null || true
echo "load-fleet: fd limit $(ulimit -n); load average: $(uptime | sed 's/.*load averages*: //')"

mkdir -p "$WORK/bin" "$WORK/keys" "$OUT"
echo "load-fleet: building"
go build -o "$WORK/bin/halo" ./cmd/halo
go build -o "$WORK/bin/halo-server" ./cmd/halo-server
# A prebuilt server (a release binary, or one with a profiler) can stand in for the one just built.
[ -z "${LOAD_FLEET_SERVER_BIN:-}" ] || cp "$LOAD_FLEET_SERVER_BIN" "$WORK/bin/halo-server"
go build -tags loadfleet -o "$WORK/bin/fleet" ./test/load/fleet
"$WORK/bin/halo" keys generate --out "$WORK/keys" >/dev/null
"$WORK/bin/halo" keys generate --name killswitch --out "$WORK/keys" >/dev/null
openssl rand -hex 32 >"$WORK/gateway.token"
openssl rand -hex 32 >"$WORK/fleet.token"
openssl rand -hex 32 >"$WORK/session.key"
SHA=$(printf 'a%.0s' $(seq 64))
cat >"$WORK/portal.json" <<JSON
{"baseURL":"http://$LISTEN","registry":"127.0.0.1:5000/halos","pubKeyFile":"$WORK/keys/halo.pub",
 "halodURL":"https://downloads.example.com/halod-{os}-{arch}","halodSHA256":{"linux-amd64":"$SHA"},
 "sessionKeyFile":"$WORK/session.key"}
JSON

stop_server() {
  if [ -n "$SRV_PID" ]; then
    kill "$SRV_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    SRV_PID=""
  fi
}

# start_server <mode> <name>: fresh state, then wait until ready.
start_server() {
  local mode=$1 name=$2 store
  case $mode in
    file)
      /bin/rm -rf "$WORK/data"
      store=(--data-dir "$WORK/data")
      ;;
    pg)
      if [ -n "${LOAD_FLEET_DATABASE_URL:-}" ]; then
        psql "$LOAD_FLEET_DATABASE_URL" -v ON_ERROR_STOP=1 -qc 'DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;' >/dev/null
        printf '%s\n' "$LOAD_FLEET_DATABASE_URL" >"$WORK/dburl"
      else
        docker rm -f "$PGC" >/dev/null 2>&1 || true
        docker run -d --name "$PGC" -e POSTGRES_USER=halos -e POSTGRES_PASSWORD=loadfleet -e POSTGRES_DB=halos \
          -p "127.0.0.1:$PGPORT:5432" postgres:16-alpine >/dev/null
        for _ in $(seq 60); do docker exec "$PGC" pg_isready -U halos -d halos >/dev/null 2>&1 && break; sleep 1; done
        sleep 2 # the image restarts the server once after its init scripts
        for _ in $(seq 30); do docker exec "$PGC" pg_isready -U halos -d halos >/dev/null 2>&1 && break; sleep 1; done
        printf 'postgres://halos:loadfleet@127.0.0.1:%s/halos?sslmode=disable\n' "$PGPORT" >"$WORK/dburl"
      fi
      "$WORK/bin/halo-server" migrate --database-url-file "$WORK/dburl" >/dev/null
      store=(--database-url-file "$WORK/dburl")
      ;;
  esac
  env ${LOAD_FLEET_GOMAXPROCS:+GOMAXPROCS=$LOAD_FLEET_GOMAXPROCS} "$WORK/bin/halo-server" \
    --policy-dir examples/acme-corp --token-file "$WORK/fleet.token" --listen "$LISTEN" --metrics-listen "$METRICS" \
    --dev-insecure-user loadtest@example.com --dev-insecure-admin --portal-config "$WORK/portal.json" \
    --killswitch-key-file "$WORK/keys/killswitch.key" --gateway-token-file "$WORK/gateway.token" \
    "${store[@]}" >"$OUT/$name.server.log" 2>&1 &
  SRV_PID=$!
  for _ in $(seq 60); do
    curl -fsS --max-time 3 "http://$LISTEN/readyz" >/dev/null 2>&1 && return 0
    kill -0 "$SRV_PID" 2>/dev/null || break
    sleep 1
  done
  echo "load-fleet: server never became ready" >&2
  tail -20 "$OUT/$name.server.log" >&2
  exit 1
}

: >"$OUT/summary.md"
rc=0
for mode in $MODES; do
  if [ "$mode" = pg ] && [ -z "${LOAD_FLEET_DATABASE_URL:-}" ] && ! docker info >/dev/null 2>&1; then
    echo "load-fleet: skipping pg (no Docker and no LOAD_FLEET_DATABASE_URL)"
    continue
  fi
  for sc in $SCENARIOS; do
    n=${sc%x*}
    scale=${sc#*x}
    name=$mode-${n}x$scale
    echo "load-fleet: === $name (load average: $(uptime | sed 's/.*load averages*: //')) ==="
    start_server "$mode" "$name"
    la=$(uptime | sed 's/.*load averages*: //')
    if "$WORK/bin/fleet" -server "http://$LISTEN" -devices "$n" -scale "$scale" -server-pid "$SRV_PID" \
      -metrics "http://$METRICS/metrics" -label "$name, load average at start: $la" -out "$OUT/$name" ${EXTRA[@]+"${EXTRA[@]}"}; then
      :
    else
      rc=1
    fi
    cat "$OUT/$name/report.md" >>"$OUT/summary.md" 2>/dev/null || true
    if [ "$mode" = pg ]; then # what the run left in the database, for Postgres sizing
      if [ -n "${LOAD_FLEET_DATABASE_URL:-}" ]; then
        pgq() { psql "$LOAD_FLEET_DATABASE_URL" -Atc "$1"; }
      else
        pgq() { docker exec "$PGC" psql -U halos -d halos -Atc "$1"; }
      fi
      {
        echo "### Postgres size after $name"
        echo
        echo '```'
        echo "database: $(pgq 'SELECT pg_size_pretty(pg_database_size(current_database()))')"
        pgq "SELECT relname || ': ' || n_live_tup || ' rows, ' || pg_size_pretty(pg_total_relation_size(relid)) FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 6"
        echo '```'
        echo
      } >>"$OUT/summary.md" 2>&1 || true
    fi
    stop_server
  done
done
echo "load-fleet: report in $OUT/summary.md"
exit $rc
