#!/usr/bin/env bash
# release.sh — cut a Halos release: preflight, then create and push the annotated tag.
# .github/workflows/release.yml does the rest (gate, GoReleaser, attestations, verify).
#
#   scripts/release.sh [--dry-run] [--yes] vX.Y.Z|vX.Y.Z-rc.N
#
#   --dry-run  run every preflight check, report all failures, push nothing
#   --yes      skip the confirmation prompt before pushing the tag
#
# Preflight: on main, clean tree, HEAD == origin/main, tag is strict SemVer and free,
# CHANGELOG has a non-empty section for it, the latest main CI run is green for HEAD,
# `go test ./...` and `goreleaser check` pass. This script never pushes a branch;
# CHANGELOG/version changes land on main by PR first (main is protected).
set -euo pipefail

DRY=0 YES=0 TAG=
for a in "$@"; do
  case $a in
    --dry-run) DRY=1 ;;
    --yes) YES=1 ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    -*) echo "release.sh: unknown flag $a" >&2; exit 2 ;;
    *) [ -z "$TAG" ] || { echo "release.sh: one tag only" >&2; exit 2; }; TAG=$a ;;
  esac
done
[ -n "$TAG" ] || { sed -n '5,8p' "$0" >&2; exit 2; }

ok()   { printf '\033[32m✓\033[0m %s\n' "$*"; }
info() { printf '  %s\n' "$*"; }
FAILS=0
fail() { # dry-run reports every failure; a real run stops at the first
  printf '\033[31m✗\033[0m %s\n' "$*" >&2
  FAILS=$((FAILS + 1))
  [ "$DRY" = 1 ] || exit 1
}
die() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

[[ $TAG =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc\.[1-9][0-9]*)?$ ]] \
  || die "tag $TAG is not vX.Y.Z or vX.Y.Z-rc.N"
FINAL=${TAG%%-*}
ok "tag $TAG is strict SemVer"

ROOT=$(git rev-parse --show-toplevel) || die "not in a git repository"
cd "$ROOT"
HERE=$(cd "$(dirname "$0")" && pwd)

branch=$(git symbolic-ref --short -q HEAD || true)
if [ "$branch" = main ]; then ok "on main"; else fail "on '${branch:-detached HEAD}', not main"; fi

if [ -z "$(git status --porcelain)" ]; then ok "working tree clean"; else fail "working tree is dirty (git status)"; fi

git fetch -q origin main --tags || die "git fetch origin failed"
HEAD=$(git rev-parse HEAD)
if [ "$HEAD" = "$(git rev-parse origin/main)" ]; then ok "HEAD is origin/main (${HEAD:0:12})"
else fail "HEAD ${HEAD:0:12} != origin/main $(git rev-parse --short=12 origin/main); pull or push first"; fi

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || [ -n "$(git ls-remote --tags origin "refs/tags/$TAG")" ]; then
  fail "tag $TAG already exists"
else ok "tag $TAG is free"; fi
if [ "$TAG" != "$FINAL" ] && [ -n "$(git ls-remote --tags origin "refs/tags/$FINAL")" ]; then
  fail "$FINAL is already released; an rc of it would sort below it"
fi

if "$HERE/release-notes.sh" "$TAG" >/dev/null; then ok "CHANGELOG has a non-empty section for $TAG"
else fail "CHANGELOG.md needs that section for $TAG; land it on main by PR"; fi

if command -v gh >/dev/null 2>&1; then
  run=$(gh run list --workflow ci.yml --branch main --limit 1 --json headSha,status,conclusion \
    --jq '.[0] | "\(.headSha) \(.status) \(.conclusion)"' 2>/dev/null || true)
  read -r sha status concl <<<"${run:-none none none}"
  if [ "$sha" != "$HEAD" ]; then fail "latest main CI run is for ${sha:0:12}, not HEAD ${HEAD:0:12}; wait for it"
  elif [ "$status/$concl" != completed/success ]; then fail "main CI for HEAD is $status/$concl"
  else ok "main CI is green for HEAD"; fi
else fail "gh is not installed; cannot check main CI"; fi

info "go test ./... (a minute or two)"
log=$(mktemp); trap 'command rm -f "$log"' EXIT
if go test ./... >"$log" 2>&1; then ok "go test ./... passes"
else tail -20 "$log" >&2; fail "go test ./... failed"; fi

if command -v goreleaser >/dev/null 2>&1; then
  # Exit 2 means "valid but deprecated"; tolerate only the known `brews` deprecation.
  set +e; out=$(goreleaser check 2>&1); rc=$?; set -e
  if [ $rc = 0 ]; then ok "goreleaser check passes"
  elif [ $rc = 2 ] && ! grep DEPRECATED <<<"$out" | grep -qv ' brews '; then ok "goreleaser check passes (known brews deprecation)"
  else printf '%s\n' "$out" >&2; fail "goreleaser check failed (exit $rc)"; fi
else fail "goreleaser is not installed; cannot check .goreleaser.yaml"; fi

[ "$FAILS" = 0 ] || die "$FAILS preflight check(s) failed; not releasing $TAG"

if [ "$DRY" = 1 ]; then
  ok "dry run: all checks pass. Would run:"
  info "git tag -a $TAG -m $TAG ${HEAD:0:12} && git push origin refs/tags/$TAG"
  exit 0
fi

if [ "$YES" != 1 ]; then
  kind=final; [ "$TAG" = "$FINAL" ] || kind="prerelease (soak; no tap/bucket, no :latest)"
  read -r -p "Tag ${HEAD:0:12} as $TAG ($kind) and push it? [y/N] " ans
  [[ $ans =~ ^[Yy]$ ]] || die "aborted"
fi
git tag -a "$TAG" -m "$TAG" "$HEAD"
git push origin "refs/tags/$TAG"
ok "$TAG pushed; the release workflow is running"
info "watch: https://github.com/dshakes/halos/actions/workflows/release.yml"
info "the 'verify' job checks signatures, attestations, images, install.sh and (final) tap/bucket"
