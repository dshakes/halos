#!/usr/bin/env bash
# Run every native Go fuzz target (func Fuzz*) in the module for FUZZTIME each.
# PR CI uses a short budget, the nightly workflow a long one. A crasher fails the
# run; its input lands in <pkg>/testdata/fuzz/<Target>/ (uploaded by CI) and
# becomes a permanent seed once committed.
set -euo pipefail
FUZZTIME="${FUZZTIME:-30s}"
cd "$(dirname "$0")/.."

fail=0
for pkg in $(go list ./...); do
  for t in $(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true); do
    echo "== $pkg $t ($FUZZTIME)"
    go test -run '^$' -fuzz "^${t}\$" -fuzztime "$FUZZTIME" "$pkg" || fail=1
  done
done
exit "$fail"
