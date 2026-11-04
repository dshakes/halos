#!/bin/bash
# Real end-to-end UAT of features/coder: Coder server (docker) + docker template + workspaces that run the
# module's coder_script against a local TLS OCI registry and an https halod server (release .tar.gz and raw binary).
# Needs Docker, Go, curl, openssl, python3, tar. Linux amd64 or macOS arm64 Docker Desktop.
# Everything created is labelled halos-uat=coder and removed on exit (KEEP=1 keeps it).
# shellcheck disable=SC2086,SC2016 # $L/$ids are word lists; single quotes are commands for the remote shell
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
cd "$ROOT"
TPL=$HERE/coder-template
CODER_VER=${CODER_VER:-v2.38.6}
W=$(mktemp -d); mkdir -p "$W/bin" "$W/srv/halod/linux-arm64" "$W/srv/halod/linux-amd64" "$W/srv/evil" "$W/ctx"
export GOBIN=$W/bin PATH="$W/bin:$PATH" CODER_CONFIG_DIR=$W/coderconf
PIDS=(); PASS=0; NFAIL=0
L="--label halos-uat=coder"
cleanup() {
  for p in ${PIDS[@]+"${PIDS[@]}"}; do kill "$p" 2>/dev/null || true; done
  [ "${KEEP:-0}" = 1 ] && return
  ids=$(docker ps -aq --filter label=halos-uat=coder); [ -z "$ids" ] || docker rm -f -v $ids >/dev/null 2>&1 || true
  docker network rm halos-uat-net >/dev/null 2>&1 || true
  docker image rm halos-uat-ws:local >/dev/null 2>&1 || true
}
trap cleanup EXIT
ok()  { echo "PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $*"; NFAIL=$((NFAIL+1)); }
chk() { local d=$1; shift; if "$@" >"$W/chk.out" 2>&1; then ok "$d"; else bad "$d"; sed 's/^/    /' "$W/chk.out"; fi; }

echo "== build halo/halod, keys, TLS, registry, https server"
go build -o "$W/bin/halo" ./cmd/halo
GOOS=linux GOARCH=$(go env GOARCH) go build -o "$W/halo-linux" ./cmd/halo   # macOS Go ignores SSL_CERT_FILE, so publish from Linux
# The workspace arch is the Docker daemon's (Docker Desktop on Apple silicon: arm64; Linux CI: amd64).
case "$(docker info --format '{{.Architecture}}')" in x86_64) DA=amd64 ;; *) DA=arm64 ;; esac
sha() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
for a in arm64 amd64; do GOOS=linux GOARCH=$a go build -o "$W/srv/halod/linux-$a/halod" ./cmd/halod; done
# What the release ships: halod_<ver>_linux_<arch>.tar.gz with halod at the top level.
for a in arm64 amd64; do tar -czf "$W/srv/halod/halod_linux_$a.tar.gz" -C "$W/srv/halod/linux-$a" halod; done
mkdir "$W/evil"; ln -s /bin/sh "$W/evil/halod"; tar -czf "$W/srv/evil/halod_linux_$DA.tar.gz" -C "$W/evil" halod   # halod is a symlink
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=halos-uat" -keyout "$W/tls.key" -out "$W/tls.pem" \
  -addext "subjectAltName=DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
go install github.com/distribution/distribution/v3/cmd/registry@v3.0.0
printf 'version: 0.1\nstorage:\n  inmemory: {}\nhttp:\n  addr: 0.0.0.0:15443\n  tls:\n    certificate: %s\n    key: %s\n' "$W/tls.pem" "$W/tls.key" > "$W/registry.yml"
registry serve "$W/registry.yml" >"$W/registry.log" 2>&1 & PIDS+=($!)
cat > "$W/https.py" <<PY
import http.server, ssl, functools
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory="$W/srv")
s = http.server.ThreadingHTTPServer(("0.0.0.0", 18443), h)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain("$W/tls.pem", "$W/tls.key")
s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()
PY
python3 "$W/https.py" >"$W/https.log" 2>&1 & PIDS+=($!)
export SSL_CERT_FILE=$W/tls.pem
halo keys generate --out "$W/keys" >/dev/null
halo keys generate --out "$W/keys2" >/dev/null
for _ in $(seq 30); do curl -fs --cacert "$W/tls.pem" "https://localhost:15443/v2/" >/dev/null && break; sleep 1; done
echo "== workspace image (enterprise-base + throwaway CA)"
cp "$W/tls.pem" "$W/ctx/ca.pem"
cat > "$W/ctx/Dockerfile" <<'DF'
FROM codercom/enterprise-base:ubuntu
USER root
COPY ca.pem /usr/local/share/ca-certificates/halos-uat.crt
RUN update-ca-certificates && apt-get update -qq && apt-get install -y -qq --no-install-recommends nodejs npm
USER coder
DF
docker build -q $L -t halos-uat-ws:local "$W/ctx" >/dev/null

echo "== publish signed release of examples/acme-corp (ring0-harness-team)"
docker run --rm $L --add-host host.docker.internal:host-gateway -e XDG_STATE_HOME=/tmp \
  -v "$W:/w:ro" -v "$ROOT/examples/acme-corp:/pol:ro" halos-uat-ws:local \
  /w/halo-linux release publish /pol --ring ring0-harness-team --release-version 1.0.0 --key /w/keys/halo.key --registry host.docker.internal:15443/halos/rel | tee "$W/publish.out"

echo "== Coder server $CODER_VER"
docker network create $L halos-uat-net >/dev/null
docker run -d $L --name halos-uat-pg --network halos-uat-net -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=coder postgres:16-alpine >/dev/null
for _ in $(seq 30); do docker exec halos-uat-pg pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
sleep 3
docker run -d $L --name halos-uat-coder --network halos-uat-net --user 0:0 -p 7080:7080 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CODER_PG_CONNECTION_URL="postgresql://postgres:pw@halos-uat-pg/coder?sslmode=disable" \
  -e CODER_HTTP_ADDRESS=0.0.0.0:7080 -e CODER_ACCESS_URL=http://host.docker.internal:7080 \
  --add-host host.docker.internal:host-gateway \
  ghcr.io/coder/coder:$CODER_VER >/dev/null
for _ in $(seq 90); do curl -fs http://localhost:7080/api/v2/buildinfo >"$W/buildinfo.json" 2>/dev/null && break; sleep 2; done
echo "coder server: $(cat "$W/buildinfo.json")"
OS=$(uname -s | tr '[:upper:]' '[:lower:]'); case "$(uname -m)" in x86_64) CA=amd64;; *) CA=arm64;; esac
curl -fsSL "http://localhost:7080/bin/coder-$OS-$CA" -o "$W/bin/coder"; chmod +x "$W/bin/coder"
coder version | head -1
coder login http://localhost:7080 --first-user-username uat --first-user-email uat@example.com \
  --first-user-password 'Uat-Passw0rd!x9' --first-user-full-name UAT --first-user-trial=false >/dev/null
echo "logged in: $(coder whoami 2>&1 | head -1)"

echo "== template"
cp -R "$TPL" "$W/tpl"; mkdir -p "$W/tpl/halos"; cp features/coder/main.tf "$W/tpl/halos/main.tf"
{
  echo "registry: host.docker.internal:15443/halos/rel"; echo "org: acme-corp"; echo "ring: ring0-harness-team"
  echo "arch: $DA"; echo "image: halos-uat-ws:local"
  echo "tgz_url: https://host.docker.internal:18443/halod/halod_linux_{arch}.tar.gz"; echo "tgz_sha: $(sha "$W/srv/halod/halod_linux_$DA.tar.gz")"
  echo "raw_url: https://host.docker.internal:18443/halod/linux-{arch}/halod"; echo "raw_sha: $(sha "$W/srv/halod/linux-$DA/halod")"
  echo "evil_url: https://host.docker.internal:18443/evil/halod_linux_{arch}.tar.gz"; echo "evil_sha: $(sha "$W/srv/evil/halod_linux_$DA.tar.gz")"
  echo "pubkey_pem: |"; sed 's/^/  /' "$W/keys/halo.pub"
  echo "other_pubkey_pem: |"; sed 's/^/  /' "$W/keys2/halo.pub"
} > "$W/vars.yaml"
coder templates push halos-uat -d "$W/tpl" --variables-file "$W/vars.yaml" --yes 2>&1 | tail -15

mkws() { coder create "$1" --template halos-uat --parameter "mode=$2" --yes 2>&1 | tail -25 || true; }
wsexec() { coder ssh "$1" -- "${@:2}"; }
lifecycle() { coder list -o json | python3 -c 'import json,sys
w=[x for x in json.load(sys.stdin) if x["name"]==sys.argv[1]][0]
a=[a for r in w["latest_build"]["resources"] for a in (r.get("agents") or [])][0]
print(a["lifecycle_state"])' "$1"; }

waitlc() { for _ in $(seq 120); do s=$(lifecycle "$1" 2>/dev/null || true); case $s in ready|start_error|start_timeout) return;; esac; sleep 3; done; }
echo "== good workspace"
mkws uat-good good; waitlc uat-good
chk "good: agent lifecycle ready (coder_script succeeded)" test "$(lifecycle uat-good)" = ready
echo "-- halod status"; wsexec uat-good "sudo /usr/local/lib/halos/halod status" | tee "$W/status.out" || true
DIG=$(grep -o 'sha256:[0-9a-f]\{64\}' "$W/publish.out" | head -1)
echo "published digest: $DIG"
chk "good: halod status reports published release digest" grep -q "${DIG:?no digest in publish output}" "$W/status.out"
chk "good: halod.yaml carries the workspace owner's email as subject" wsexec uat-good 'grep -qx "subject: \"uat@example.com\"" /etc/halos/halod.yaml'
chk "good: halod installed from the .tar.gz as a root-owned regular file" wsexec uat-good 'test "$(stat -c %U:%a /usr/local/lib/halos/halod)" = root:755 && test ! -L /usr/local/lib/halos/halod'
chk "good: claude managed-settings.json disableBypassPermissionsMode=disable" wsexec uat-good 'grep -q "\"disableBypassPermissionsMode\": *\"disable\"" /etc/claude-code/managed-settings.json'
chk "good: claude-code installed" wsexec uat-good 'claude --version'
wsexec uat-good 'ls -l /etc/claude-code /etc/codex /etc/halos 2>&1; cat /etc/claude-code/managed-settings.json; cat /etc/codex/requirements.toml 2>&1' | tee "$W/files.out" || true
chk "good: codex requirements.toml present" wsexec uat-good 'test -s /etc/codex/requirements.toml'
coder ssh uat-good -- 'cat /etc/claude-code/managed-settings.json /etc/codex/requirements.toml 2>/dev/null' > "$W/managed.all" || true
chk "good: no bypassPermissions/danger-full-access in managed files" sh -c "test -s $W/managed.all && ! grep -E 'bypassPermissions|danger-full-access' $W/managed.all"
chk "good: files root-owned, mode 0644 or tighter" wsexec uat-good 'for f in /etc/claude-code/managed-settings.json /etc/codex/requirements.toml /etc/halos/halod.yaml /etc/halos/release.pub; do m=$(stat -c "%U:%a" $f); echo "$f $m"; case $m in root:644|root:640|root:600|root:444|root:400) ;; *) exit 1;; esac; done'

echo "== goodraw: raw-binary halod_url"
mkws uat-goodraw goodraw; waitlc uat-goodraw
chk "goodraw: agent lifecycle ready" test "$(lifecycle uat-goodraw)" = ready
chk "goodraw: halod status reports published release digest" wsexec uat-goodraw "sudo /usr/local/lib/halos/halod status | grep -q $DIG"

for m in badsha badkey badtar; do
  echo "== negative: $m"
  mkws uat-$m $m; waitlc uat-$m
  wsexec uat-$m 'ls /etc/claude-code /etc/codex 2>&1; ls -l /usr/local/lib/halos 2>&1; cat /etc/halos/halod.yaml 2>&1' | tee "$W/$m.out" || true
  echo "lifecycle: $(lifecycle uat-$m)"
  [ "$m" = badkey ] || chk "$m: halod not installed" wsexec uat-$m '! test -e /usr/local/lib/halos/halod'   # badkey passes the sha pin
  chk "$m: script failed (start_error)" test "$(lifecycle uat-$m)" = start_error
  chk "$m: no managed settings applied" wsexec uat-$m '! test -e /etc/claude-code/managed-settings.json && ! test -e /etc/codex/requirements.toml'
  echo "-- $m script log"; wsexec uat-$m 'tail -8 /tmp/coder-script-data/*.log 2>/dev/null; ls /tmp | head' || true
done
echo; echo "RESULT: $PASS passed, $NFAIL failed"; [ "$NFAIL" = 0 ]
