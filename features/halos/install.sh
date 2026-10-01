#!/usr/bin/env bash
# Halos Dev Container Feature. Options arrive as upper-case env vars.
# The halod binary is sha256-pinned and the release public key is supplied inline
# (or pinned by hash): release contents are ed25519-verified against that key
# before anything is applied. The firewall is NOT started here (image build has
# no NET_ADMIN and iptables state does not persist); it is installed and run at
# container start via the feature's `entrypoint`.
set -euo pipefail

REGISTRY="${REGISTRY:-}"
ORG="${ORG:-}"
RING="${RING:-ga}"
PUBKEYPEM="${PUBKEYPEM:-}"
PUBKEY="${PUBKEY:-}"
PUBKEYSHA256="${PUBKEYSHA256:-}"
HALODURL="${HALODURL:-}"
HALODSHA256="${HALODSHA256:-}"
GATEWAYHOST="${GATEWAYHOST:-}"
FIREWALL="${FIREWALL:-false}"

die() { echo "halos: $*" >&2; exit 1; }

[ -n "$REGISTRY" ]  || die "'registry' option is required"
[ -n "$HALODURL" ]    || die "'halodUrl' option is required"
[ -n "$HALODSHA256" ] || die "'halodSha256' option is required"
[ -n "$PUBKEYPEM" ] || [ -n "$PUBKEY" ] || die "'pubkeyPem' option is required"

[ -n "$ORG" ] || die "'org' option is required"
[[ "$ORG" =~ ^[a-z0-9][a-z0-9._-]{0,62}$ ]] || die "invalid org"
[[ "$RING" =~ ^[a-z0-9][a-z0-9._-]{0,62}$ ]] || die "invalid ring"
[[ "$REGISTRY" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?(/[a-zA-Z0-9][a-zA-Z0-9._-]*)+$ ]] || die "invalid registry"
[[ "$HALODURL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%+@,=\&?{}-]*)*$ ]] || die "halodUrl must be a plain https URL"
if [ -n "$GATEWAYHOST" ]; then
  [[ "$GATEWAYHOST" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || die "invalid gatewayHost"
fi

# pkg_install <apt-pkgs> <apk-pkgs> <dnf-pkgs>: build-time only; fails the feature build if no manager.
pkg_install() {
  # shellcheck disable=SC2086 # intentional word splitting of package lists
  if command -v apt-get >/dev/null; then
    apt-get update -y && apt-get install -y --no-install-recommends $1
  elif command -v apk >/dev/null; then apk add --no-cache $2
  elif command -v dnf >/dev/null; then dnf install -y $3
  else die "no supported package manager (apt-get, apk, dnf) to install: $1"; fi
}

command -v curl >/dev/null || pkg_install "curl ca-certificates" "curl ca-certificates" "curl ca-certificates"
# The firewall never installs packages at container start (egress is closed by then).
if [ "$FIREWALL" = "true" ]; then
  pkg_install "iptables ipset dnsutils" "iptables ip6tables ipset bind-tools" "iptables ipset bind-utils"
  for t in iptables ipset dig curl; do command -v "$t" >/dev/null || die "firewall tool missing after install: $t"; done
fi

sha_check() { # sha_check <hex> <file>
  if command -v sha256sum >/dev/null; then echo "$1  $2" | sha256sum -c - >/dev/null
  else echo "$1  $2" | shasum -a 256 -c - >/dev/null; fi
}

os=linux
case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) die "unsupported arch" ;; esac

# halodSha256: bare hex, or "amd64=<hex>,arm64=<hex>".
want="$HALODSHA256"
if [[ "$want" == *=* ]]; then
  want=$(tr ',' '\n' <<<"$want" | sed -n "s/^${arch}=//p")
fi
[[ "$want" =~ ^[0-9a-fA-F]{64}$ ]] || die "halodSha256 missing or malformed for $arch"

url="${HALODURL//\{os\}/$os}"; url="${url//\{arch\}/$arch}"
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp"
sha_check "$want" "$tmp" || die "halod sha256 mismatch"
install -d -o 0 -g 0 -m 0755 /usr/local/lib/halos /etc/halos /var/lib/halos
install -o 0 -g 0 -m 0755 "$tmp" /usr/local/lib/halos/halod
ln -sf /usr/local/lib/halos/halod /usr/local/bin/halod

if [ -n "$PUBKEYPEM" ]; then
  printf '%s\n' "${PUBKEYPEM//\\n/$'\n'}" > "$tmp"
else
  [[ "$PUBKEY" == https://* ]] || die "'pubkey' must be an https URL (or use pubkeyPem)"
  [[ "$PUBKEYSHA256" =~ ^[0-9a-fA-F]{64}$ ]] || die "'pubkey' URL requires 'pubkeySha256'"
  curl -fsSL "$PUBKEY" -o "$tmp"
  sha_check "$PUBKEYSHA256" "$tmp" || die "pubkey sha256 mismatch"
fi
if ! { grep -qx -e '-----BEGIN PUBLIC KEY-----' "$tmp" && grep -qx -e '-----END PUBLIC KEY-----' "$tmp" \
  && ! grep -qvE '^(-----(BEGIN|END) PUBLIC KEY-----|[A-Za-z0-9+/=]+)$' "$tmp"; }; then
  die "public key is not a single PUBLIC KEY PEM block"
fi
install -o 0 -g 0 -m 0644 "$tmp" /etc/halos/release.pub

# halod refuses config/key/state that are not root-owned and non-writable by others.
install -o 0 -g 0 -m 0644 /dev/null /etc/halos/halod.yaml
printf 'registry: %s\norg: %s\nring: %s\npubkey: /etc/halos/release.pub\nos: linux\n' "$REGISTRY" "$ORG" "$RING" > /etc/halos/halod.yaml

# Always installed (the feature entrypoint runs it); it is a no-op without firewall-hosts.
install -o 0 -g 0 -m 0755 "$(dirname "$0")/init-firewall.sh" /usr/local/bin/halos-init-firewall
if [ "$FIREWALL" = "true" ]; then
  [ -n "$GATEWAYHOST" ] || die "firewall needs gatewayHost"
  echo "${GATEWAYHOST} ${REGISTRY%%/*}" > /etc/halos/firewall-hosts
fi

# Apply the release now (installs pinned CLIs, writes managed settings) while the network is open.
/usr/local/lib/halos/halod once --install
