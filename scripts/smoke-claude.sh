#!/usr/bin/env bash
# Real-CLI smoke: the pinned Claude Code installed by halod through the VERIFIED
# artifact path, with managed settings from examples/acme-corp, in a Debian
# container. Needs Docker + network (downloads.claude.ai, registry.npmjs.org).
# Never uses API keys: nothing here talks to the Anthropic API.
#
#   scripts/smoke-claude.sh            # or: make smoke
#
# Flow: halo release publish (artifacts resolved from downloads.claude.ai, signed)
#   -> registry:2 on a private docker network -> halod once as root in debian
#   -> assert managed-settings.json == halo render, claude --version == pin
#   -> move the managed version window off the pin and record what claude does.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
POLICY=${POLICY:-$ROOT/examples/acme-corp}
RING=${RING:-ring3-ga}
IMAGE=${IMAGE:-debian:bookworm-slim}
ID="halo-smoke-$$"
WORK=$(mktemp -d)
NET="$ID-net"

cleanup() {
  docker rm -f "$ID-reg" "$ID-host" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

log() { printf '\n== %s\n' "$*"; }
fail() { printf 'SMOKE FAIL: %s\n' "$*" >&2; exit 1; }

ARCH=$(docker version -f '{{.Server.Arch}}')
log "build halo (host) + halod (linux/$ARCH)"
(cd "$ROOT" && go build -o "$WORK/halo" ./cmd/halo && CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -o "$WORK/halod" ./cmd/halod)

log "registry:2 on $NET"
docker network create --label halos-e2e=1 "$NET" >/dev/null
docker run -d --rm --label halos-e2e=1 --name "$ID-reg" --network "$NET" --network-alias registry -p 127.0.0.1::5000 registry:2 >/dev/null
PORT=$(docker port "$ID-reg" 5000/tcp | head -1 | sed 's/.*://')
for _ in $(seq 50); do curl -fsS "http://127.0.0.1:$PORT/v2/" >/dev/null 2>&1 && break; sleep 0.2; done

VER="smoke.$(date +%s)"
log "publish $POLICY ring $RING as v$VER (resolves + pins vendor artifacts)"
"$WORK/halo" keys generate --out "$WORK" >/dev/null
"$WORK/halo" release publish "$POLICY" --ring "$RING" --release-version "$VER" --key "$WORK/halo.key" \
  --registry "127.0.0.1:$PORT/smoke/rel" --plain-http
"$WORK/halo" render "$POLICY" --ring "$RING" --os linux --release-version "$VER" --out "$WORK/rendered" >/dev/null
PIN=$(sed -n 's/.*"requiredMinimumVersion": *"\([^"]*\)".*/\1/p' "$WORK/rendered/etc/claude-code/managed-settings.json")
[ -n "$PIN" ] || fail "rendered managed-settings has no requiredMinimumVersion"
echo "pinned claude-code: $PIN"

ORG=$(sed -n 's/^org: *//p' "$POLICY/halos.yaml")
cat >"$WORK/halod.yaml" <<EOF
registry: registry:5000/smoke/rel
org: $ORG
ring: $RING
pubkey: /etc/halos/release.pub
plainHTTP: true
EOF

log "debian host: halod once as root (verified install)"
docker run -d --label halos-e2e=1 --name "$ID-host" --network "$NET" "$IMAGE" sleep infinity >/dev/null
# nodejs/npm (root-owned distro package): halod's npm-tgz installs for codex / gemini-cli need it.
docker exec "$ID-host" sh -c 'apt-get update -qq >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends ca-certificates nodejs npm >/dev/null'
docker exec "$ID-host" mkdir -p /etc/halos /usr/local/sbin
docker cp "$WORK/halod" "$ID-host:/usr/local/sbin/halod"
docker cp "$WORK/halod.yaml" "$ID-host:/etc/halos/halod.yaml"
docker cp "$WORK/halo.pub" "$ID-host:/etc/halos/release.pub"
docker exec "$ID-host" sh -c 'chown -R root:root /etc/halos /usr/local/sbin/halod && chmod 644 /etc/halos/*'
set +e
docker exec "$ID-host" /usr/local/sbin/halod once
SYD_RC=$?
set -e
echo "halod once exit=$SYD_RC"

log "managed settings: applied == halo render"
docker exec "$ID-host" cat /etc/claude-code/managed-settings.json >"$WORK/applied.json" || fail "halod did not write /etc/claude-code/managed-settings.json"
diff -u "$WORK/rendered/etc/claude-code/managed-settings.json" "$WORK/applied.json" || fail "applied managed settings differ from halo render"
echo "identical"

log "claude --version == $PIN"
GOT=$(docker exec "$ID-host" claude --version 2>&1) || fail "claude --version failed: $GOT"
echo "claude --version: $GOT"
case "$GOT" in "$PIN"*) ;; *) fail "installed claude reports '$GOT', pin is $PIN";; esac
docker exec "$ID-host" cat /var/lib/halos/state.json | sed -n '/"harnesses"/,/}/p'
[ "$SYD_RC" = 0 ] || echo "NOTE: halod exited $SYD_RC (see errors above; claude itself installed)"

log "version gate (no credentials; nothing reaches the API)"
# Observed on 2.1.280: `claude --version` and `claude doctor` never enforce the
# managed window; `claude -p` checks it at startup, before auth or network.
window() { # min max
  docker exec "$ID-host" sh -c "sed -i 's/\"requiredMinimumVersion\": *\"[^\"]*\"/\"requiredMinimumVersion\": \"$1\"/; s/\"requiredMaximumVersion\": *\"[^\"]*\"/\"requiredMaximumVersion\": \"$2\"/' /etc/claude-code/managed-settings.json"
  docker exec "$ID-host" grep -E 'required(Min|Max)imumVersion' /etc/claude-code/managed-settings.json | tr -d ' ,' | tr '\n' ' '; echo
}
probe() { # prints output of a credential-less `claude -p`
  docker exec -e HOME=/root "$ID-host" timeout 60 sh -c 'claude -p hello </dev/null' 2>&1 || true
}
GATE='by your organization' # "...older than the minimum version required|newer than the maximum version allowed by your organization"

window "$PIN" "$PIN"
OUT=$(probe); printf -- '--- in window: claude -p hello\n%s\n' "$(echo "$OUT" | head -5)"
case "$OUT" in *"$GATE"*) fail "version gate fired for the pinned version";; esac

window 99.0.0 99.0.0
OUT=$(probe); printf -- '--- min above installed: claude -p hello\n%s\n' "$(echo "$OUT" | head -5)"
case "$OUT" in *"older than the minimum version required $GATE"*) ;; *) fail "claude started although requiredMinimumVersion > installed";; esac
printf -- '--- min above installed: claude --version (not gated): %s\n' "$(docker exec "$ID-host" claude --version 2>&1)"

window 1.0.0 2.0.0
OUT=$(probe); printf -- '--- max below installed: claude -p hello\n%s\n' "$(echo "$OUT" | head -5)"
case "$OUT" in *"newer than the maximum version allowed $GATE"*) ;; *) fail "claude started although requiredMaximumVersion < installed";; esac

log "SMOKE OK (pin $PIN)"
