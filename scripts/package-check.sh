#!/usr/bin/env bash
# Packaging checks, local only (nothing is pushed anywhere). Needs Docker.
#   scripts/package-check.sh snapshot      goreleaser snapshot; verify archives + checksums (+SBOMs if syft)
#   scripts/package-check.sh snapshot images   (images needs the snapshot's docker images; they are removed on exit)
#   images: smoke the snapshot service images + eval images + fake-driver eval run
#   scripts/package-check.sh feature       Dev Container Feature e2e (TLS registry, signed release, firewall)
#   scripts/package-check.sh clean         remove everything labelled halos-pkgtest=1 and snapshot images
# Scratch lives in $PKGTEST_DIR (default: a fresh mktemp dir, removed on exit unless KEEP=1).
# Every container/network/volume/built image carries the label halos-pkgtest=1.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
GORELEASER="${GORELEASER:-github.com/goreleaser/goreleaser/v2@v2.18.2}"
L=halos-pkgtest=1
W="${PKGTEST_DIR:-$(mktemp -d)}"
mkdir -p "$W"
ARCH=$(docker version --format '{{.Server.Arch}}' | sed 's/aarch64/arm64/;s/x86_64/amd64/')
IMAGES=(halo-server halo-proxy halo-shadow kong-halo)
die() { echo "package-check: $*" >&2; exit 1; }
ok() { echo "OK   $*"; }

clean() {
  docker ps -aq --filter "label=$L" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network ls -q --filter "label=$L" | xargs -r docker network rm >/dev/null 2>&1 || true
  docker volume ls -q --filter "label=$L" | xargs -r docker volume rm >/dev/null 2>&1 || true
  docker image ls -q --filter "label=$L" | sort -u | xargs -r docker rmi -f >/dev/null 2>&1 || true
  docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -E '^(halos-pkgtest/|vsc-ws-)' | xargs -r docker rmi -f >/dev/null 2>&1 || true
  docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -E '^ghcr.io/dshakes/(halo-server|halo-proxy|halo-shadow|kong-halo):(.*SNAPSHOT|latest-(amd64|arm64))$' \
    | xargs -r docker rmi -f >/dev/null 2>&1 || true
  docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -E '^ghcr.io/dshakes/eval-[a-z]+:' \
    | xargs -r docker rmi -f >/dev/null 2>&1 || true
  [ -n "${PKGTEST_SRV:-}" ] && kill "$PKGTEST_SRV" 2>/dev/null || true
  [ "${KEEP:-}" = 1 ] || case "$W" in /tmp/*|/var/folders/*|/private/*) rm -rf "$W" ;; esac
}
[ "${1:-}" = clean ] && { clean; exit 0; }
trap clean EXIT

snapshot() {
  # Temp config copy so the repo stays clean; dist goes to scratch.
  { echo "dist: $W/dist"; cat .goreleaser.yaml; } >"$W/goreleaser.yaml"
  skip=publish,sign; command -v syft >/dev/null || { skip=$skip,sbom; echo "NOTE syft not on PATH: SBOMs UNVERIFIED"; }
  go run "$GORELEASER" release --snapshot --clean --skip="$skip" --config "$W/goreleaser.yaml"
  cd "$W/dist"
  n=0
  for a in *.tar.gz *.zip; do
    b=${a%%_*}; e=$b; case $a in *windows*) e=$b.exe ;; esac
    case $a in *.zip) l=$(unzip -Z1 "$a") ;; *) l=$(tar tzf "$a") ;; esac
    grep -qx "$e" <<<"$l" || die "$a lacks $e"
    grep -q " $a\$" checksums.txt || die "$a missing from checksums.txt"
    n=$((n + 1))
  done
  (shasum -a 256 -c checksums.txt >/dev/null) || die "checksum mismatch"
  [ "$n" = 32 ] || die "expected 32 archives (5 binaries x 6 targets + halo-kong x 2), got $n"
  command -v syft >/dev/null && { [ "$(ls ./*.sbom.json 2>/dev/null | wc -l)" = "$n" ] || die "SBOM count != archive count"; }
  ok "$n archives contain their binary, all listed in checksums.txt and verified"
  cd "$ROOT"
}

snap_tag() { docker image ls --format '{{.Tag}}' "ghcr.io/dshakes/$1" | grep -E "SNAPSHOT.*-$ARCH\$" | head -1; }

svc_check() { # svc_check <image> : non-root user, size
  local ref="ghcr.io/dshakes/$1:$(snap_tag "$1")"
  docker image inspect "$ref" --format '{{.Config.User}}' | grep -Eq '^(nonroot|kong|[1-9][0-9]*)' || die "$1 runs as root"
  echo "SIZE $1 $(docker image inspect "$ref" --format '{{.Size}}') bytes (user $(docker image inspect "$ref" --format '{{.Config.User}}'))"
  echo "$ref"
}

images() {
  [ -n "$(snap_tag halo-server)" ] || die "no snapshot images; run: make snapshot"
  tok=pkgtest-token-0123456789abcdef
  mkdir -p "$W/pol"; echo -n "$tok" >"$W/tok"
  ref=$(svc_check halo-server | tail -1)
  docker run -d --name pkt-server --label $L --read-only --cap-drop ALL -v "$W/pol:/pol:ro" -v "$W/tok:/tok:ro" -p 127.0.0.1:0:8080 \
    "$ref" -listen 0.0.0.0:8080 -dev-insecure-user dev -policy-dir /pol -token-file /tok >/dev/null
  ref=$(svc_check halo-shadow | tail -1)
  docker run -d --name pkt-shadow --label $L --read-only --cap-drop ALL -v pkt-data:/data -e HALO_SHADOW_TOKEN=$tok -p 127.0.0.1:0:8090 \
    "$ref" -listen 0.0.0.0:8090 -policy /none.json >/dev/null
  ref=$(svc_check halo-proxy | tail -1)
  docker run -d --name pkt-proxy --label $L --read-only --cap-drop ALL -p 127.0.0.1:0:9090 \
    "$ref" -admin-listen 0.0.0.0:9090 -listen 0.0.0.0:8080 -policy /none.json -allow-anonymous >/dev/null
  sleep 3
  for p in "server 8080 200" "shadow 8090 200" "proxy 9090 503"; do # proxy: 503 until a policy loads
    set -- $p; port=$(docker port "pkt-$1" "$2" | head -1 | sed 's/.*://')
    code=$(curl -s -m5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/healthz")
    [ "$code" = "$3" ] || { docker logs "pkt-$1" 2>&1 | tail -3; die "$1 /healthz = $code, want $3"; }
    ok "$1 /healthz $code (read-only rootfs, caps dropped, non-root)"
  done
  kong
  evals
}

kong() {
  ref=$(svc_check kong-halo | tail -1)
  mkdir -p "$W/kong"
  cat >"$W/kong/kong.yml" <<'E'
_format_version: "3.0"
services:
  - name: up
    url: http://127.0.0.1:9
    routes: [{name: r, paths: [/]}]
    plugins: [{name: halo-kong, config: {policy_path: /etc/halo/policy.json}}]
E
  docker run -d --name pkt-kong --label $L --read-only --tmpfs /tmp:mode=1777 --cap-drop ALL -e KONG_PREFIX=/tmp/kong \
    -e KONG_DECLARATIVE_CONFIG=/k/kong.yml -e KONG_ADMIN_LISTEN=0.0.0.0:8001 -v "$W/kong:/k:ro" -p 127.0.0.1:0:8001 "$ref" >/dev/null
  port=$(docker port pkt-kong 8001 | head -1 | sed 's/.*://')
  for _ in $(seq 30); do curl -sf "http://127.0.0.1:$port/plugins/enabled" >"$W/plugins.json" 2>/dev/null && break; sleep 1; done
  grep -q '"halo-kong"' "$W/plugins.json" || die "halo-kong not in /plugins/enabled"
  docker exec -e KONG_PREFIX=/tmp/kong pkt-kong kong health >/dev/null || die "kong health failed"
  ok "kong-halo: kong health, halo-kong in /plugins/enabled (read-only rootfs, user kong)"
}

evals() { # real DockerRunner path against Docker with a stub `claude`; real CLIs only --version
  for h in claude:2.1.280 codex:0.58.0 gemini:0.12.0; do
    n=${h%%:*}; v=${h##*:}
    docker build -q --label $L --build-arg CLI_VERSION="$v" -t "ghcr.io/dshakes/eval-$n:$v" "evals/images/$n" >/dev/null
    echo "SIZE eval-$n:$v $(docker image inspect "ghcr.io/dshakes/eval-$n:$v" --format '{{.Size}}') bytes"
    docker run --rm --label $L --network none "ghcr.io/dshakes/eval-$n:$v" sh -c "test \$(id -un) = eval && go version >/dev/null && git --version >/dev/null && $n --version" >/dev/null
  done
  docker build -q --label $L -t ghcr.io/dshakes/eval-claude:fake evals/images/fake >/dev/null
  mkdir -p "$W/es/suites"; ln -sfn "$ROOT/evals/tasks" "$W/es/tasks"
  printf 'name: fake\ntasks: [fix-failing-go-test]\ncontrol: a\nrepeats: 2\nvariants:\n  - {name: a, harness: claude, version: fake, model: sonnet}\n  - {name: b, harness: claude, version: fake, model: sonnet}\n' >"$W/es/suites/fake.yaml"
  go build -o "$W/halo" ./cmd/halo
  "$W/halo" eval run "$W/es/suites/fake.yaml" --output json >"$W/sc.json"
  python3 -c "import json,sys;t=json.load(open('$W/sc.json'))['trials'];sys.exit(0 if len(t)==4 and all(x['pass'] for x in t) else 1)" || die "fake eval trials did not all pass"
  [ -z "$(docker ps -aq --filter name=halo-eval-)" ] || die "eval containers leaked"
  ok "halo eval run via DockerRunner: 4/4 trials pass, no leaked containers"
}

feature() {
  F=$W/ft; mkdir -p "$F/certs" "$F/reg" "$F/ws/.devcontainer" "$F/static/halod/linux-arm64" "$F/static/halod/linux-amd64"
  RELPORT=${RELPORT:-55000}; SRVPORT=${SRVPORT:-55100}
  HOST=host.docker.internal
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$F/certs/key.pem" -out "$F/certs/ca.pem" -subj "/CN=halos-pkgtest-ca" \
    -addext "subjectAltName=DNS:$HOST,DNS:localhost,DNS:pkt-gateway" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
  chmod 644 "$F"/certs/*
  go build -o "$W/halo" ./cmd/halo
  for a in amd64 arm64; do CGO_ENABLED=0 GOOS=linux GOARCH=$a go build -trimpath -o "$F/static/halod/linux-$a/halod" ./cmd/halod; done
  (cd "$F" && "$W/halo" keys generate --name rel >/dev/null)
  # Two registries over one store: plain HTTP on loopback for `halo release publish`, TLS for halod in the container.
  docker run -d --name pkt-reg-http --label $L -v "$F/reg:/var/lib/registry" -p 127.0.0.1:0:5000 registry:2 >/dev/null
  docker run -d --name pkt-reg-tls --label $L -v "$F/reg:/var/lib/registry" -v "$F/certs:/certs:ro" -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/ca.pem \
    -e REGISTRY_HTTP_TLS_KEY=/certs/key.pem -p 0.0.0.0:$RELPORT:5000 registry:2 >/dev/null
  docker network create --label $L pkt-net >/dev/null
  docker run -d --name pkt-gateway --network pkt-net --label $L -v "$F/certs:/certs:ro" -e REGISTRY_HTTP_ADDR=:443 \
    -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/ca.pem -e REGISTRY_HTTP_TLS_KEY=/certs/key.pem registry:2 >/dev/null
  cat >"$F/srv.py" <<'E'
import functools, http.server, ssl, sys
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory=sys.argv[2])
s = http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), h)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(sys.argv[3], sys.argv[4])
s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()
E
  python3 "$F/srv.py" $SRVPORT "$F/static" "$F/certs/ca.pem" "$F/certs/key.pem" >"$F/srv.log" 2>&1 &
  PKGTEST_SRV=$!
  sleep 2
  hp=$(docker port pkt-reg-http 5000 | head -1 | sed 's/.*://')
  # Needs network for vendor artifacts; NO_ARTIFACTS=1 checks the fail-closed path instead.
  art=(); [ "${NO_ARTIFACTS:-}" = 1 ] && art=(--no-artifacts)
  "$W/halo" release publish --policy-dir examples/acme-corp --registry "127.0.0.1:$hp/halos/rel" --plain-http --key "$F/rel.key" \
    --ring ring1-canary --release-version 0.0.1 ${art[@]+"${art[@]}"} >/dev/null
  rm_ws="$F/ws/.devcontainer"
  cp -R features/halos "$rm_ws/halos"; rm -r "$rm_ws/halos/example"
  cp "$F/certs/ca.pem" "$rm_ws/ca.crt"
  cat >"$rm_ws/Dockerfile" <<'E'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl nodejs npm
COPY ca.crt /usr/local/share/ca-certificates/pkt-ca.crt
RUN update-ca-certificates
E
  python3 - "$F" "$HOST" "$RELPORT" "$SRVPORT" <<'E'
import hashlib, json, sys
F, host, rp, sp = sys.argv[1:]
h = lambda a: hashlib.sha256(open(f"{F}/static/halod/linux-{a}/halod", "rb").read()).hexdigest()
json.dump({"name": "pkt", "build": {"dockerfile": "Dockerfile"}, "features": {"./halos": {
    "registry": f"{host}:{rp}/halos/rel", "org": "acme-corp", "ring": "ring1-canary",
    "pubkeyPem": open(f"{F}/rel.pub").read().strip().replace("\n", "\\n"),
    "halodUrl": f"https://{host}:{sp}/halod/linux-{{arch}}/halod",
    "halodSha256": f"amd64={h('amd64')},arm64={h('arm64')}", "gatewayHost": "pkt-gateway", "firewall": True}},
    "runArgs": ["--cap-add=NET_ADMIN", "--cap-add=NET_RAW", "--network=pkt-net", "--label=halos-pkgtest=1"]},
    open(f"{F}/ws/.devcontainer/devcontainer.json", "w"), indent=1)
E
  (cd "$F/ws" && npx -y @devcontainers/cli@latest up --workspace-folder . >"$F/up.log" 2>&1) || { tail -30 "$F/up.log"; die "devcontainer up failed"; }
  C=$(docker ps -q --filter label=devcontainer.local_folder | head -1)
  docker update --label-add $L "$C" >/dev/null 2>&1 || true
  for _ in $(seq 60); do docker logs "$C" 2>&1 | grep -q '^firewall: egress restricted' && break; sleep 2; done
  docker logs "$C" 2>&1 | grep -q '^firewall: egress restricted' || { docker logs "$C" 2>&1 | tail; die "firewall did not come up"; }
  docker exec "$C" sh -c '
    set -e
    [ "$(stat -c %U:%G /usr/local/lib/halos/halod)" = root:root ]
    [ "$(stat -c %U:%G /etc/halos/halod.yaml)" = root:root ]
    grep -qx "org: acme-corp" /etc/halos/halod.yaml; grep -qx "ring: ring1-canary" /etc/halos/halod.yaml
    test -x /usr/local/bin/halos-init-firewall; test -s /etc/claude-code/managed-settings.json
    ! curl -s --max-time 5 -o /dev/null https://example.com
    curl -s --max-time 8 -o /dev/null https://pkt-gateway/v2/
    curl -s --max-time 8 -o /dev/null https://'"$HOST:$RELPORT"'/v2/' || die "in-container assertions failed"
  ok "feature: halod root-owned, halod.yaml org/ring, managed settings, firewall blocks example.com, allows gateway+registry"
}

[ $# -gt 0 ] || die "usage: $0 snapshot|images|feature|clean [...]"
for step in "$@"; do
  case "$step" in
    snapshot|images|feature) "$step" ;;
    *) die "unknown step $step" ;;
  esac
done
