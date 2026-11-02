#!/usr/bin/env bash
# SAML interop UAT (ADR-0039): halo-server as SAML SP against a real IdP, Keycloak in Docker.
# Drives an SP-initiated login with curl only (no browser), then the negative cases.
# Needs: docker, go, curl, openssl. No secrets; the image is pulled from quay.io.
set -euo pipefail

KC_IMAGE="${KC_IMAGE:-quay.io/keycloak/keycloak:26.4.7@sha256:9409c59bdfb65dbffa20b11e6f18b8abb9281d480c7ca402f51ed3d5977e6007}"
HALO_PORT="${HALO_PORT:-18480}"
KC_PORT="${KC_PORT:-18481}"
NAME="halos-uat-saml-$$"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
SP="http://127.0.0.1:${HALO_PORT}"
KC="http://127.0.0.1:${KC_PORT}"
ENTITY="${SP}/auth/saml/metadata"
ACR_MFA="urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor"
SRV_PID=""
fails=0

cleanup() {
  rc=$?
  if [ -n "$SRV_PID" ]; then kill "$SRV_PID" 2>/dev/null || true; fi
  if [ "$rc" != 0 ]; then
    echo "uat-saml: failed (exit $rc)" >&2
    tail -n 30 "$WORK/server.log" 2>/dev/null >&2 || true
    docker logs --tail 30 "$NAME" 2>&1 >&2 || true
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

check() { # name ok(0|1) detail
  if [ "$2" = 0 ]; then echo "  [PASS] $1: $3"; else echo "  [FAIL] $1: $3"; fails=$((fails + 1)); fi
}

kcadm() { docker exec -i "$NAME" /opt/keycloak/bin/kcadm.sh "$@"; }

# HTML-unescape the entities Keycloak puts in form attributes.
unescape() { sed -e 's/&amp;/\&/g' -e 's/&#61;/=/g' -e 's/&#x3d;/=/gi' -e 's/&#43;/+/g' -e 's/&#x2b;/+/gi' -e 's/&#47;/\//g' -e 's/&#x2f;/\//gi'; }

# field <html-file> <input-name>: value of a hidden input.
field() { grep -o "name=\"$2\"[^>]*" "$1" | head -n1 | sed -n 's/.*value="\([^"]*\)".*/\1/p' | unescape; }

echo "== Keycloak ($KC_IMAGE)"
docker run -d --name "$NAME" -p "127.0.0.1:${KC_PORT}:8080" \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -e KC_HOSTNAME_STRICT=false -e KC_HTTP_ENABLED=true \
  "$KC_IMAGE" start-dev >/dev/null
for _ in $(seq 1 90); do
  curl -sf "$KC/realms/master" >/dev/null 2>&1 && break
  sleep 2
done
curl -sf "$KC/realms/master" >/dev/null
kcadm config credentials --server http://localhost:8080 --realm master --user admin --password admin >/dev/null

kcadm create realms -s realm=halos -s enabled=true >/dev/null
kcadm create clients -r halos -f - >/dev/null <<EOF
{
  "clientId": "${ENTITY}",
  "protocol": "saml",
  "enabled": true,
  "redirectUris": ["${SP}/auth/saml/acs"],
  "attributes": {
    "saml_assertion_consumer_url_post": "${SP}/auth/saml/acs",
    "saml.assertion.signature": "true",
    "saml.server.signature": "false",
    "saml.signature.algorithm": "RSA_SHA256",
    "saml.client.signature": "false",
    "saml_name_id_format": "username",
    "saml.force.post.binding": "true"
  },
  "protocolMappers": [{
    "name": "groups", "protocol": "saml", "protocolMapper": "saml-group-membership-mapper",
    "config": {"attribute.name": "groups", "attribute.nameformat": "Basic", "single": "false", "full.path": "false"}
  }]
}
EOF
gid="$(kcadm create groups -r halos -s name=ai-platform -i)"
uid="$(kcadm create users -r halos -s username=alice -s enabled=true -s email=alice@acme.example \
  -s emailVerified=true -s firstName=Alice -s lastName=Admin -i)"
kcadm set-password -r halos --username alice --new-password 'S3cret-pass!' >/dev/null
kcadm update "users/${uid}/groups/${gid}" -r halos -s realm=halos -s userId="$uid" -s groupId="$gid" -n >/dev/null
curl -sf "$KC/realms/halos/protocol/saml/descriptor" -o "$WORK/idp-metadata.xml"

echo "== halo-server"
openssl req -x509 -newkey rsa:3072 -sha256 -days 2 -nodes -subj "/CN=halos-saml" \
  -keyout "$WORK/sp.key" -out "$WORK/sp.crt" 2>/dev/null
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$WORK/session.key"
echo "uat-saml-token" >"$WORK/token"
printf '{"baseURL":"%s","sessionKeyFile":"%s"}\n' "$SP" "$WORK/session.key" >"$WORK/portal.json"
(cd "$ROOT" && go build -o "$WORK/halo-server" ./cmd/halo-server)

# acme-corp already maps group ai-platform to admin; drop its OIDC issuer so only SAML is on.
policy() { # policy <dir> [requireAcr]
  rm -rf "$1"
  cp -R "$ROOT/examples/acme-corp" "$1"
  grep -v -e '^  issuer:' -e '^  clientID:' "$ROOT/examples/acme-corp/halos.yaml" >"$1/halos.yaml"
  if [ -n "${2:-}" ]; then sed -i.bak "s|^  adminGroups:|  requireAcr: [\"$2\"]\n  adminGroups:|" "$1/halos.yaml" && rm "$1/halos.yaml.bak"; fi
}

start_server() { # start_server <policy-dir>
  if [ -n "$SRV_PID" ]; then kill "$SRV_PID" 2>/dev/null || true; wait "$SRV_PID" 2>/dev/null || true; fi
  "$WORK/halo-server" --policy-dir "$1" --token-file "$WORK/token" --listen "127.0.0.1:${HALO_PORT}" \
    --portal-config "$WORK/portal.json" \
    --saml-idp-metadata-file "$WORK/idp-metadata.xml" \
    --saml-sp-key-file "$WORK/sp.key" --saml-sp-cert-file "$WORK/sp.crt" >>"$WORK/server.log" 2>&1 &
  SRV_PID=$!
  for _ in $(seq 1 30); do
    curl -sf "$SP/auth/methods" 2>/dev/null | grep -q '"saml":true' && return 0
    sleep 1
  done
  echo "halo-server did not report saml:true" >&2
  return 1
}

# login <jar> <password> <out-prefix>: SP-initiated; leaves <prefix>.resp (Keycloak's reply) behind.
login() {
  local jar="$1" pw="$2" p="$3" form
  rm -f "$jar"
  curl -s -L -c "$jar" -b "$jar" -o "$p.login.html" "$SP/auth/saml/login"
  form="$(grep -o 'action="[^"]*"' "$p.login.html" | head -n1 | sed 's/^action="//;s/"$//' | unescape)"
  [ -n "$form" ] || { echo "no Keycloak login form (see $p.login.html)" >&2; return 1; }
  curl -s -c "$jar" -b "$jar" -o "$p.resp" --data-urlencode username=alice \
    --data-urlencode "password=$pw" --data-urlencode credentialId= "$form"
}

# acs <jar> <resp-file> <out-prefix>: POST the SAMLResponse to the SP; prints the status.
acs() {
  curl -s -c "$1" -b "$1" -o "$3.acs" -w '%{http_code}' "$SP/auth/saml/acs" \
    --data-urlencode "SAMLResponse=$(field "$2" SAMLResponse)" \
    --data-urlencode "RelayState=$(field "$2" RelayState)"
}

has_session() { grep -q "halo_session" "$1"; }

echo "== happy path"
policy "$WORK/policy"
start_server "$WORK/policy"
check metadata "$(curl -sf "$SP/auth/saml/metadata" | grep -q EntityDescriptor && echo 0 || echo 1)" "SP metadata served"
login "$WORK/jar" 'S3cret-pass!' "$WORK/ok"
[ -n "$(field "$WORK/ok.resp" SAMLResponse)" ]
code="$(acs "$WORK/jar" "$WORK/ok.resp" "$WORK/ok")"
check acs-302 "$([ "$code" = 302 ] && echo 0 || echo 1)" "ACS answered $code"
check session-cookie "$(has_session "$WORK/jar" && echo 0 || echo 1)" "halo_session set"
me="$(curl -s -b "$WORK/jar" "$SP/api/v1/me")"
echo "  /api/v1/me: $me"
check me-user "$(echo "$me" | grep -q '"alice"' && echo 0 || echo 1)" "user alice"
check me-group "$(echo "$me" | grep -q 'ai-platform' && echo 0 || echo 1)" "group ai-platform"
check me-admin "$(echo "$me" | grep -q 'admin' && echo 0 || echo 1)" "admin role"

echo "== replay (a fresh browser has no spent-request cookie, so this is refused before the id check; id single-use is covered by the Go tests)"
rm -f "$WORK/jar2"
code="$(acs "$WORK/jar2" "$WORK/ok.resp" "$WORK/replay")"
check replay-refused "$([ "$code" != 302 ] && ! has_session "$WORK/jar2" && echo 0 || echo 1)" "replayed SAMLResponse: $code, no session"
code="$(acs "$WORK/jar" "$WORK/ok.resp" "$WORK/replay2")"
check replay-same-browser "$([ "$code" != 302 ] && echo 0 || echo 1)" "replay in the original browser: $code"

echo "== wrong password"
login "$WORK/bad" 'wrong-pass' "$WORK/bad"
check wrong-password "$([ -z "$(field "$WORK/bad.resp" SAMLResponse)" ] && ! has_session "$WORK/bad" && echo 0 || echo 1)" "Keycloak issued no SAMLResponse, no session"

echo "== requireAcr unmet"
policy "$WORK/policy-acr" "$ACR_MFA"
start_server "$WORK/policy-acr"
login "$WORK/jar3" 'S3cret-pass!' "$WORK/acr"
if [ -n "$(field "$WORK/acr.resp" SAMLResponse)" ]; then
  code="$(acs "$WORK/jar3" "$WORK/acr.resp" "$WORK/acr")"
  check require-acr "$([ "$code" = 403 ] && ! has_session "$WORK/jar3" && echo 0 || echo 1)" "ACS answered $code ($(head -c 120 "$WORK/acr.acs" | tr -d '\n')), no session"
else
  # Keycloak refused the RequestedAuthnContext itself: still no session.
  check require-acr "$(has_session "$WORK/jar3" && echo 1 || echo 0)" "IdP refused the requested AuthnContext; no session"
fi

echo
if [ "$fails" = 0 ]; then echo "uat-saml: all checks passed (Keycloak: $KC_IMAGE)"; else echo "uat-saml: $fails check(s) failed"; exit 1; fi
