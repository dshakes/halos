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
    out=$(go test -run '^$' -fuzz "^${t}\$" -fuzztime "$FUZZTIME" "$pkg" 2>&1) && { echo "$out"; continue; }
    echo "$out"
    # Go's engine can end a run with "context deadline exceeded" and no input
    # when a worker is mid-exec at the deadline (I/O-heavy targets). That is
    # not a finding: retry once. A real crasher always writes its input.
    if ! grep -q 'Failing input written to' <<<"$out" && grep -q 'context deadline exceeded' <<<"$out"; then
      echo "== retry $t: engine deadline without a failing input"
      go test -run '^$' -fuzz "^${t}\$" -fuzztime "$FUZZTIME" "$pkg" || fail=1
    else
      fail=1
    fi
  done
done
exit "$fail"
