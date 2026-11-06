#!/usr/bin/env bash
# govulncheck, failing on any vulnerability our code calls unless it is listed
# in .govulncheck-accept with a reason and an expiry date (YYYY-MM-DD). Each
# entry must name the mitigation; an expired entry fails again, so an
# acceptance cannot outlive its review.
set -euo pipefail
cd "$(dirname "$0")/.."
out=$(mktemp); trap 'rm -f "$out"' EXIT
go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 -format json ./... >"$out"
python3 - "$out" .govulncheck-accept <<'PY'
import datetime, json, sys
dec, buf, called = json.JSONDecoder(), open(sys.argv[1]).read(), set()
i = 0
while i < len(buf):
    while i < len(buf) and buf[i].isspace():
        i += 1
    if i >= len(buf):
        break
    msg, i = dec.raw_decode(buf, i)
    f = msg.get("finding")
    if f and f.get("trace") and f["trace"][0].get("function"):  # symbol level: our code reaches it
        called.add(f["osv"])
accepted, today = {}, datetime.date.today()
for n, line in enumerate(open(sys.argv[2]), 1):
    line = line.split("#", 1)[0].strip()
    if not line:
        continue
    osv, expires, *reason = line.split(None, 2)
    if not reason:
        sys.exit(f".govulncheck-accept:{n}: want '<ID> <YYYY-MM-DD> <mitigation>'")
    accepted[osv] = (datetime.date.fromisoformat(expires), reason[0])
bad = 0
for osv in sorted(called):
    if osv not in accepted:
        print(f"FAIL {osv}: called by our code: https://pkg.go.dev/vuln/{osv}"); bad = 1
    elif accepted[osv][0] < today:
        print(f"FAIL {osv}: acceptance expired {accepted[osv][0]}; re-review it"); bad = 1
    else:
        print(f"accepted {osv} until {accepted[osv][0]}: {accepted[osv][1]}")
for osv in sorted(set(accepted) - called):
    print(f"note: {osv} is accepted but no longer reported; remove it from .govulncheck-accept")
print("govulncheck:", "FAIL" if bad else "OK", f"({len(called)} called)")
sys.exit(bad)
PY
