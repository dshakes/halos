#!/bin/bash
# CI only (ubuntu-latest, Docker, network): the dev container delivery path through the real devcontainer CLI.
#   A. .devcontainer/devcontainer.json (this repo's own dev container): build + up, then go/node are the
#      pinned toolchains and postCreateCommand (`make build`) produced a working bin/halo.
#   B. features/halos consumed as a local Feature by a fixture dev container whose base image trusts a
#      throwaway CA: the Feature fetches a sha256-pinned halod over HTTPS and applies a real signed
#      release (claude-code 2.1.280, from `halo init --full`) from an HTTPS registry. Asserts the
#      pinned CLI and the managed settings land in the container.
# Not run: Codespaces, Coder, the firewall option (needs NET_ADMIN), a published Feature OCI artifact.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD
W=$(mktemp -d)
mkdir -p "$W/bin" "$W/srv/halod/linux-amd64"
export GOBIN=$W/bin PATH="$W/bin:$PATH"
PIDS=()
trap 'for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
dc() { devcontainer "$@"; }

echo "== A: repo .devcontainer"
dc up --workspace-folder "$ROOT" --remove-existing-container
dcx() { dc exec --workspace-folder "$ROOT" "$@"; }
dcx go version | grep -q 'go1\.26\.6' || fail "go toolchain is not the pinned 1.26.6"
dcx node --version
dcx bin/halo version
dcx bin/halo validate examples/acme-corp
dcx docker version --format '{{.Server.Version}}' || fail "docker-in-docker not available"

echo "== B: halos Feature via the devcontainer CLI"
GW=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
[ -n "$GW" ] || fail "no docker bridge gateway"
REG=$GW:5443
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=halos-ci" -keyout "$W/tls.key" -out "$W/tls.pem" \
  -addext "subjectAltName=IP:$GW" -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
go build -o "$W/bin/halo" ./cmd/halo
GOOS=linux GOARCH=amd64 go build -o "$W/srv/halod/linux-amd64/halod" ./cmd/halod
go install github.com/distribution/distribution/v3/cmd/registry@v3.0.0
printf 'version: 0.1\nstorage:\n  inmemory: {}\nhttp:\n  addr: 0.0.0.0:5443\n  tls:\n    certificate: %s\n    key: %s\n' "$W/tls.pem" "$W/tls.key" > "$W/registry.yml"
registry serve "$W/registry.yml" >"$W/registry.log" 2>&1 & PIDS+=($!)
cat > "$W/https.py" <<PY
import http.server, ssl, functools
h = functools.partial(http.server.SimpleHTTPRequestHandler, directory="$W/srv")
s = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), h)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain("$W/tls.pem", "$W/tls.key")
s.socket = c.wrap_socket(s.socket, server_side=True); s.serve_forever()
PY
python3 "$W/https.py" >"$W/https.log" 2>&1 & PIDS+=($!)

export SSL_CERT_FILE=$W/tls.pem
halo init "$W/pol" --org acme --full >/dev/null
halo keys generate --out "$W/keys" >/dev/null
for _ in $(seq 30); do curl -fs --cacert "$W/tls.pem" "https://$REG/v2/" >/dev/null && break; sleep 1; done
halo release publish "$W/pol" --ring ring1-ga --release-version 1.0.0 --key "$W/keys/halo.key" --registry "$REG/halos/rel"

FX=$W/fx
mkdir -p "$FX/.devcontainer/halos"
for f in install.sh init-firewall.sh devcontainer-feature.json; do command cp "features/halos/$f" "$FX/.devcontainer/halos/$f"; done
command cp "$W/tls.pem" "$FX/.devcontainer/ca.pem"
cat > "$FX/.devcontainer/Dockerfile" <<'DF'
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl
COPY ca.pem /usr/local/share/ca-certificates/halos-ci.crt
RUN update-ca-certificates
DF
SHA=$(sha256sum "$W/srv/halod/linux-amd64/halod" | cut -d' ' -f1)
PEM=$(sed ':a;N;$!ba;s/\n/\\n/g' "$W/keys/halo.pub")
cat > "$FX/.devcontainer/devcontainer.json" <<JSON
{
  "name": "halos-feature-ci",
  "build": {"dockerfile": "Dockerfile"},
  "features": {
    "./halos": {
      "registry": "$REG/halos/rel", "org": "acme", "ring": "ring1-ga",
      "pubkeyPem": "$PEM",
      "halodUrl": "https://$GW:8443/halod/linux-{arch}/halod", "halodSha256": "amd64=$SHA"
    }
  }
}
JSON
dc up --workspace-folder "$FX" --remove-existing-container
fx() { dc exec --workspace-folder "$FX" "$@"; }
fx sh -c 'claude --version' | grep -q '2\.1\.280' || fail "pinned claude-code 2.1.280 not installed"
fx sh -c 'cat /etc/claude-code/managed-settings.json' | grep -q '"disableBypassPermissionsMode": *"disable"' || fail "managed settings missing/incorrect"
fx sh -c 'stat -c "%U:%a" /etc/claude-code/managed-settings.json' | grep -qx 'root:644' || fail "managed settings not root-owned 644"
fx sh -c 'cat /etc/halos/halod.yaml' | grep -q "ring: ring1-ga" || fail "feature did not write halod.yaml"
echo "dev container delivery path OK"
