#!/bin/sh
# Halos installer for macOS and Linux.
#   sh install.sh [--version vX.Y.Z] [--prefix DIR] [--with-agent]
# Installs halo (and halod with --with-agent) into DIR/bin (default ~/.local).
# Verifies checksums.txt against its cosign signature when cosign is on PATH
# (else warns loudly and trusts the sha256 only), then each archive against
# checksums.txt. Never uses sudo; pick a prefix you can write, or run it as root.
# --with-agent runs as root, so it needs a root-owned prefix: sudo sh install.sh --prefix /usr/local --with-agent
set -eu

REPO=dshakes/halos
VERSION=${HALOS_VERSION:-}
PREFIX=${HALOS_PREFIX:-$HOME/.local}
WITH_AGENT=0

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case $1 in
    --version) [ $# -ge 2 ] || die "--version needs a value"; VERSION=$2; shift 2 ;;
    --prefix) [ $# -ge 2 ] || die "--prefix needs a value"; PREFIX=$2; shift 2 ;;
    --with-agent) WITH_AGENT=1; shift ;;
    -h|--help) sed -n '2,7p' "$0"; exit 0 ;;
    *) die "unknown flag $1" ;;
  esac
done

# root_owned_chain DIR: DIR (or its nearest existing ancestor) and every parent is
# root-owned and not group/other-writable, so no other user can swap what we install.
root_owned_chain() {
  d=$1
  while [ ! -e "$d" ]; do d=$(dirname "$d"); done
  while :; do
    [ -n "$(find -H "$d" -maxdepth 0 -user root ! -perm -020 ! -perm -002 2>/dev/null)" ] || return 1
    [ "$d" = / ] && return 0
    d=$(dirname "$d")
  done
}
if [ "$WITH_AGENT" = 1 ]; then
  # halod runs as root and refuses (and so would we) a binary a non-root user could replace.
  case $PREFIX in /*) ;; *) die "--prefix must be an absolute path" ;; esac
  if [ "$(id -u)" != 0 ] || ! root_owned_chain "$PREFIX"; then
    die "--with-agent needs a root-owned prefix; run: sudo sh $0 --prefix /usr/local --with-agent"
  fi
fi

case $(uname -s) in
  Darwin) OS=darwin ;;
  Linux) OS=linux ;;
  *) die "unsupported OS $(uname -s); use install.ps1 on Windows" ;;
esac
case $(uname -m) in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

command -v curl >/dev/null 2>&1 || die "curl is required"
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die "sha256sum or shasum is required"
fi

if [ -z "$VERSION" ]; then
  echo "install.sh: no --version given; resolving latest (pin a version in automation)" >&2
  VERSION=$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") || die "cannot resolve latest release"
  VERSION=${VERSION##*/}
fi
case $VERSION in
  v[0-9]*) ;;
  [0-9]*) VERSION=v$VERSION ;;
  *) die "bad version $VERSION" ;;
esac
case $VERSION in *[!A-Za-z0-9._+-]*) die "bad version $VERSION" ;; esac
NUM=${VERSION#v}
BASE=https://github.com/$REPO/releases/download/$VERSION

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$TMP/$1" "$BASE/$1" || die "download $BASE/$1 failed"; }

fetch checksums.txt
if command -v cosign >/dev/null 2>&1; then
  fetch checksums.txt.sig
  fetch checksums.txt.pem
  cosign verify-blob \
    --certificate-identity "https://github.com/$REPO/.github/workflows/release.yml@refs/tags/$VERSION" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --signature "$TMP/checksums.txt.sig" --certificate "$TMP/checksums.txt.pem" \
    "$TMP/checksums.txt" >/dev/null 2>&1 || die "cosign signature verification FAILED for checksums.txt"
  echo "install.sh: cosign signature verified"
else
  echo "install.sh: WARNING: cosign not found; the signature was NOT verified." >&2
  echo "install.sh: WARNING: trusting the sha256 checksums downloaded from the same origin." >&2
fi

mkdir -p "$PREFIX/bin" || die "cannot create $PREFIX/bin"
BINS=halo
[ "$WITH_AGENT" = 1 ] && BINS="halo halod"
for b in $BINS; do
  f=${b}_${NUM}_${OS}_${ARCH}.tar.gz
  fetch "$f"
  want=$(awk -v f="$f" '$2 == f {print $1}' "$TMP/checksums.txt")
  [ -n "$want" ] || die "$f is not listed in checksums.txt"
  [ "$(sha256 "$TMP/$f")" = "$want" ] || die "sha256 mismatch for $f"
  mkdir "$TMP/x-$b"
  tar -xzf "$TMP/$f" -C "$TMP/x-$b" "$b" || die "extract $f failed"
  install -m 0755 "$TMP/x-$b/$b" "$PREFIX/bin/$b" || die "install $b into $PREFIX/bin failed"
  echo "install.sh: installed $PREFIX/bin/$b ($VERSION)"
done
case ":$PATH:" in *":$PREFIX/bin:"*) ;; *) echo "install.sh: add $PREFIX/bin to your PATH" >&2 ;; esac
[ "$WITH_AGENT" = 1 ] && echo "install.sh: halod is not enrolled or started; next: sudo $PREFIX/bin/halod service install --help"
exit 0
