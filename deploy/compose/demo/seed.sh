#!/bin/sh
# One-shot seed for `make demo` (runs in the halo CLI image, writes the shared
# /demo volume). DEV ONLY: every key and token below is generated fresh on this
# volume at demo start and dies with `make demo-down`; none is ever committed.
set -eu
halo=/usr/local/bin/app
repo=registry:5000/acme-corp/halos

if [ -f /demo/.seeded ]; then echo "seed: already seeded"; exit 0; fi

# examples/acme-corp + the demo overlay (mock IdP issuer, mock upstreams, shadow running)
rm -rf /demo/policy && mkdir -p /demo/policy
cp -R /src/acme-corp/. /demo/policy/
cp -R /src/overlay/. /demo/policy/
$halo validate /demo/policy

# throwaway signing keys: releases (halo.key) and the gateway kill list (killswitch.key)
$halo keys generate --out /demo/keys
$halo keys generate --name killswitch --out /demo/keys

# random secrets: fleet report token, gateway kill-list token, portal session key
rnd() { od -An -N24 -tx1 /dev/urandom | tr -d ' \n'; }
rnd >/demo/fleet.token
rnd >/demo/gateway.token
rnd >/demo/session.key
printf 'halo-dev-gateway-token' >/demo/otlp.token # matches HALO_OTLP_GATEWAY_TOKEN in deploy/observability
rnd >/demo/unit.salt

# signed releases for every ring into the local registry:2
for i in $(seq 30); do wget -qO- http://registry:5000/v2/ >/dev/null 2>&1 && break; sleep 1; done
n=0
for ring in ring0-harness-team ring1-canary ring2-early ring3-ga; do
  n=$((n + 1)) # one version per ring: v<version> tags are global, ring-<ring> tags point at them
  $halo release publish --policy-dir /demo/policy --ring "$ring" --release-version "2026.10.$n" \
    --key /demo/keys/halo.key --registry "$repo" --plain-http --no-artifacts \
    --state-file /demo/pointers.json
done

# compiled gateway snapshot for halo-proxy / halo-shadow
$halo gateway compile --policy-dir /demo/policy -o /demo/policy.json

cat >/demo/portal.json <<EOF
{"baseURL": "${CONSOLE_URL}", "registry": "$repo", "registryPlainHTTP": true,
 "pubKeyFile": "/demo/keys/halo.pub", "sessionKeyFile": "/demo/session.key"}
EOF
chmod -R a+rX /demo
touch /demo/.seeded
echo "seed: done"
