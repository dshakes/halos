#!/usr/bin/env bash
# Builds the npm packages for `npx @dshakesnotbot/halo` from a release's archives.
#
#   scripts/npm-build.sh VERSION ARCHIVE_DIR OUT_DIR
#
# ARCHIVE_DIR holds checksums.txt and halo_<VERSION>_<os>_<arch>.{tar.gz,zip} as published
# on the GitHub release (verify checksums.txt's Sigstore bundle first). Every archive is
# checked against checksums.txt before its binary is copied, so the npm packages carry
# exactly the signed release binaries. OUT_DIR gets one directory per package:
# halo-<os>-<arch>/ (the binary, with npm os/cpu fields) and halo/ (the launcher, which
# pins each platform package to VERSION as an optional dependency).
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 VERSION ARCHIVE_DIR OUT_DIR" >&2; exit 2; }
version=$1 archives=$2 out=$3
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "bad version '$version'" >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

# goreleaser os/arch -> npm os/cpu
platforms="darwin:amd64:darwin:x64 darwin:arm64:darwin:arm64 linux:amd64:linux:x64 linux:arm64:linux:arm64 windows:amd64:win32:x64 windows:arm64:win32:arm64"

rm -rf "$out" && mkdir -p "$out"
deps=""
for p in $platforms; do
  IFS=: read -r gos garch nos ncpu <<<"$p"
  ext=tar.gz exe=halo
  [ "$gos" = windows ] && ext=zip exe=halo.exe
  archive="halo_${version}_${gos}_${garch}.${ext}"
  want=$(awk -v f="$archive" '$2 == f || $2 == "*"f {print $1}' "$archives/checksums.txt")
  [ -n "$want" ] || { echo "$archive is not in checksums.txt" >&2; exit 1; }
  got=$(sha256 "$archives/$archive")
  [ "$got" = "$want" ] || { echo "$archive: sha256 $got, checksums.txt says $want" >&2; exit 1; }

  name="halo-${gos}-${garch}"
  dir="$out/$name"
  mkdir -p "$dir/bin"
  if [ "$ext" = zip ]; then unzip -q -o -j "$archives/$archive" "$exe" -d "$dir/bin"
  else tar -xzf "$archives/$archive" -C "$dir/bin" "$exe"; fi
  chmod 0755 "$dir/bin/$exe"
  cp "$root/LICENSE" "$dir/"
  cat >"$dir/package.json" <<EOF
{
  "name": "@dshakesnotbot/$name",
  "version": "$version",
  "description": "The halo CLI binary for $nos/$ncpu. Install @dshakesnotbot/halo instead.",
  "license": "Apache-2.0",
  "repository": {"type": "git", "url": "git+https://github.com/dshakes/halos.git"},
  "os": ["$nos"],
  "cpu": ["$ncpu"],
  "files": ["bin/"],
  "preferUnplugged": true
}
EOF
  deps="$deps${deps:+,}\"@dshakesnotbot/$name\": \"$version\""
done

mkdir -p "$out/halo"
cp -R "$root/npm/halo/bin" "$out/halo/"
cp "$root/LICENSE" "$out/halo/"
cat >"$out/halo/README.md" <<EOF
# @dshakesnotbot/halo

The \`halo\` CLI for [Halos](https://github.com/dshakes/halos): one policy repo for Claude Code, Codex and Gemini CLI, with signed releases, rollout rings and eval-gated promotion.

\`\`\`sh
npx @dshakesnotbot/halo quickstart
\`\`\`

npm installs only the prebuilt binary for your OS and CPU (macOS, Linux, Windows; x64 or arm64). The binaries are the signed release archives of v$version, checked against the release's checksums. Other install methods: https://github.com/dshakes/halos#install
EOF
cat >"$out/halo/package.json" <<EOF
{
  "name": "@dshakesnotbot/halo",
  "version": "$version",
  "description": "halo CLI for Halos: one policy for Claude Code, Codex and Gemini CLI, with signed releases, rollout rings and eval-gated promotion.",
  "license": "Apache-2.0",
  "homepage": "https://dshakes.github.io/halos/",
  "repository": {"type": "git", "url": "git+https://github.com/dshakes/halos.git"},
  "bin": {"halo": "bin/halo.js"},
  "files": ["bin/"],
  "engines": {"node": ">=18"},
  "optionalDependencies": {$deps}
}
EOF
echo "built @dshakesnotbot/halo and its platform packages for $version in $out"
