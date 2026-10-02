#!/usr/bin/env bash
# Records the landing page's terminal replay and rollout-simulator data from the
# real halo CLI. Output: docs/src/data/*.json (committed). Never hand-edit those.
#
# Needs Go and Docker (a throwaway registry:2 on 127.0.0.1:5056 so
# `halo upgrade start` can read the GA ring's signed pointer as its baseline).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
out=$root/docs/src/data
tmp=$(mktemp -d)
trap 'docker rm -f halos-site-reg >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
mkdir -p "$out"

halo=$tmp/halo
(cd "$root" && go build -o "$halo" ./cmd/halo)
version=$(cd "$root" && git rev-parse --short HEAD)
claude=${CLAUDE_VERSION:-$(npm view @anthropic-ai/claude-code version)}

docker run -d --name halos-site-reg -p 127.0.0.1:5056:5000 registry:2 >/dev/null
export HALO_REGISTRY=127.0.0.1:5056/acme/halos HALO_KEY=$tmp/k/halo.key XDG_STATE_HOME=$tmp/state
"$halo" keys generate --out "$tmp/k" >/dev/null
mkdir -p "$tmp/acme" && cd "$tmp/acme"

# Each step: the command as shown, then the command actually run.
steps=(
  "halo init --org acme|$halo init --org acme"
  "|$halo release publish --ring ring3-ga --release-version 1.0.0 --plain-http --registry $HALO_REGISTRY --key $HALO_KEY"
  "halo upgrade start claude-code $claude  # needs HALO_REGISTRY + HALO_KEY, and ring3-ga already published as the baseline|$halo upgrade start claude-code $claude --plain-http"
  "halo rollout simulate claude-code-$claude --scenario regression|$halo rollout simulate claude-code-$claude --scenario regression"
)
: > "$tmp/term.tsv"
for s in "${steps[@]}"; do
  shown=${s%%|*} run=${s#*|}
  t0=$(date +%s%N)
  o=$($run 2>&1)
  t1=$(date +%s%N)
  # setup steps (empty "shown") run but are not replayed
  [ -n "$shown" ] && printf '%s\t%s\t%s\n' "$shown" "$(( (t1 - t0) / 1000000 ))" "$(printf '%s' "$o" | base64 | tr -d '\n')" >> "$tmp/term.tsv"
done

cd "$root"
"$halo" rollout plan opus-5-5-upgrade --policy-dir examples/acme-corp --output json > "$tmp/plan.json"
for sc in healthy regression; do
  "$halo" rollout simulate opus-5-5-upgrade --policy-dir examples/acme-corp --scenario $sc --output json > "$tmp/sim-$sc.json"
done

python3 - "$tmp" "$out" "$version" "$claude" <<'EOF'
import base64, json, sys, datetime
tmp, out, version, claude = sys.argv[1:]
rec = {"recorded": datetime.date.today().isoformat(), "halo": version,
       "note": "Recorded by docs/scripts/record-site-data.sh: a fresh dir, a local registry:2 and a throwaway dev key "
               "(HALO_REGISTRY / HALO_KEY set; one setup step publishing ring3-ga as the rollback baseline is not replayed).",
       "steps": []}
for line in open(f"{tmp}/term.tsv"):
    cmd, ms, b64 = line.rstrip("\n").split("\t")
    rec["steps"].append({"cmd": cmd, "ms": int(ms), "out": base64.b64decode(b64).decode()})
json.dump(rec, open(f"{out}/terminal.json", "w"), indent=1)
sim = {"recorded": rec["recorded"], "halo": version,
       "source": "halo rollout plan|simulate opus-5-5-upgrade --policy-dir examples/acme-corp --output json",
       "plan": json.load(open(f"{tmp}/plan.json")),
       "healthy": json.load(open(f"{tmp}/sim-healthy.json")),
       "regression": json.load(open(f"{tmp}/sim-regression.json"))}
json.dump(sim, open(f"{out}/simulator.json", "w"), indent=1)
print("wrote", out)
EOF
