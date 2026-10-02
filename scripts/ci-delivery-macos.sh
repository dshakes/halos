#!/bin/bash
# CI only (macos-latest, passwordless sudo): the macOS delivery path for real.
#   1. install/install.sh against the real release ($HALOS_INSTALL_VERSION), user prefix and root --with-agent
#   2. portal enroll.sh against a local halo-server + a signed release in a local registry
#   3. halod once, then `halod service install --start` as a real launchd daemon, until managed
#      settings appear in /Library/Application Support/ClaudeCode; then `service uninstall`.
# Not run: Jamf/MDM, a logged-in console user, real vendor CLI installs (--no-artifacts release).
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${HALOS_INSTALL_VERSION:-v0.1.0-rc.2}
W=$(mktemp -d)
mkdir -p "$W/bin" "$W/srv"
export XDG_STATE_HOME=$W/state PATH="$W/bin:$PATH" GOBIN=$W/bin
REG=127.0.0.1:15055 BASE=http://127.0.0.1:18199 FILES=http://127.0.0.1:18200
SETTINGS="/Library/Application Support/ClaudeCode/managed-settings.json"
HALOD=/Library/Halos/bin/halod
PIDS=()
cleanup() { sudo "$HALOD" service uninstall >/dev/null 2>&1 || true; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
owner() { stat -f '%Su:%Sg %Lp' "$1"; }

echo "== install.sh $VERSION (user prefix, halo only)"
sh install/install.sh --version "$VERSION" --prefix "$W/prefix"
"$W/prefix/bin/halo" version
[ ! -e "$W/prefix/bin/halod" ] || fail "halod installed without --with-agent"

echo "== install.sh $VERSION --with-agent (root-owned prefix)"
sudo sh install/install.sh --version "$VERSION" --prefix /Library/Halos --with-agent
for b in halo halod; do [ "$(owner /Library/Halos/bin/$b)" = "root:wheel 755" ] || fail "$b: $(owner /Library/Halos/bin/$b)"; done
/Library/Halos/bin/halo version
if sh install/install.sh --version "$VERSION" --prefix "$W/prefix" --with-agent 2>"$W/err"; then fail "--with-agent accepted a user-owned prefix"; fi
grep -q "root-owned prefix" "$W/err" || fail "unexpected refusal: $(cat "$W/err")"

echo "== build from this checkout"
for c in halo halod halo-server; do go build -o "$W/bin/$c" "./cmd/$c"; done
go install github.com/distribution/distribution/v3/cmd/registry@v3.0.0
printf 'version: 0.1\nstorage:\n  inmemory: {}\nhttp:\n  addr: %s\n' "$REG" > "$W/registry.yml"
registry serve "$W/registry.yml" >"$W/registry.log" 2>&1 & PIDS+=($!)

halo init "$W/pol" --org acme --full >/dev/null
printf 'selfService:\n  enabled: true\n  launchers: [laptop]\n' >> "$W/pol/halos.yaml"
halo validate "$W/pol"
halo keys generate --out "$W/keys" >/dev/null
for _ in $(seq 30); do curl -fs "http://$REG/v2/" >/dev/null && break; sleep 1; done
halo release publish "$W/pol" --ring ring1-ga --release-version 1.0.0 --key "$W/keys/halo.key" \
  --registry "$REG/halos-releases" --plain-http --no-artifacts

ARCH=$(uname -m); case $ARCH in arm64) ARCH=arm64 ;; x86_64) ARCH=amd64 ;; esac
cp "$W/bin/halod" "$W/srv/halod"
SHA=$(shasum -a 256 "$W/srv/halod" | cut -d' ' -f1)
printf '{"baseURL":"%s","registry":"%s/halos-releases","registryPlainHTTP":true,"pubKeyFile":"%s/keys/halo.pub","halodURL":"%s/halod","halodSHA256":{"darwin-%s":"%s"}}' \
  "$BASE" "$REG" "$W" "$FILES" "$ARCH" "$SHA" > "$W/portal.json"
echo t > "$W/fleet.token"
python3 -m http.server 18200 --bind 127.0.0.1 --directory "$W/srv" >"$W/files.log" 2>&1 & PIDS+=($!)
halo-server --listen 127.0.0.1:18199 --policy-dir "$W/pol" --token-file "$W/fleet.token" --portal-config "$W/portal.json" \
  --data-dir "$W/data" --dev-insecure-user dev@acme.com --dev-insecure-admin >"$W/server.log" 2>&1 & PIDS+=($!)
for _ in $(seq 30); do curl -fs "$FILES/halod" >/dev/null && break; sleep 1; done
for _ in $(seq 30); do curl -fs "$BASE/healthz" >/dev/null && break; sleep 1; done

echo "== enroll.sh"
TOKEN=$(curl -fsS -X POST "$BASE/api/v1/launch/laptop" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
curl -fsSL "$BASE/enroll.sh" | sh -s -- "$TOKEN"
[ "$(owner "$HALOD")" = "root:wheel 755" ] || fail "enrolled halod: $(owner "$HALOD")"
[ "$(owner /Library/Halos/etc/halod.yaml)" = "root:wheel 600" ] || fail "halod.yaml: $(owner /Library/Halos/etc/halod.yaml)"
[ "$(owner /Library/Halos/var)" = "root:wheel 700" ] || fail "var: $(owner /Library/Halos/var)"
sudo grep -q '^plainHTTP: true' /Library/Halos/etc/halod.yaml || fail "enrolled config lacks plainHTTP for the local registry"
sudo cmp "$W/bin/halod" "$HALOD" || fail "enroll.sh did not install the pinned halod"

echo "== halod once"
sudo "$HALOD" once --install=false
[ -f "$SETTINGS" ] || fail "no managed settings at $SETTINGS"
case "$(owner "$SETTINGS")" in root:*" 644") ;; *) fail "managed settings: $(owner "$SETTINGS")" ;; esac # group is inherited from the directory (admin)
grep -q '"disableBypassPermissionsMode": *"disable"' "$SETTINGS" || fail "managed settings content: $(cat "$SETTINGS")"
curl -fsS "$BASE/api/v1/fleet" | grep -q 'dev@acme.com' || fail "device missing from the fleet view"

echo "== halod service install --start (launchd)"
sudo rm -f "$SETTINGS"
sudo "$HALOD" service install --start
[ "$(owner /Library/LaunchDaemons/dev.halos.halod.plist)" = "root:wheel 644" ] || fail "plist: $(owner /Library/LaunchDaemons/dev.halos.halod.plist)"
for _ in $(seq 60); do [ -f "$SETTINGS" ] && break; sleep 2; done
[ -f "$SETTINGS" ] || { sudo cat /Library/Halos/var/halod.log || true; fail "launchd daemon never wrote managed settings"; }
sudo launchctl print system/dev.halos.halod | grep -q 'state = running' || fail "daemon not running"
echo "== halod service uninstall"
sudo "$HALOD" service uninstall
[ ! -e /Library/LaunchDaemons/dev.halos.halod.plist ] || fail "plist left behind"
if sudo launchctl print system/dev.halos.halod >/dev/null 2>&1; then fail "daemon still loaded"; fi
sleep 2
if pgrep -x halod >/dev/null; then fail "halod still running after uninstall"; fi
echo "macOS delivery path OK"
