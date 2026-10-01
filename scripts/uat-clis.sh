#!/usr/bin/env bash
# Real-CLI UAT (test/uat, build tag uat): the pinned Claude Code, Codex, Gemini
# and Copilot CLIs from examples/acme-corp, installed by the Halos Dev Container
# Feature (install.sh -> halod once --install from a signed release on a TLS
# registry), driven headlessly through a real halo-proxy to mock upstreams
# (test/uat/mock), plus `halo eval run` with the real claude/codex drivers.
# Needs Docker + network (npm, downloads.claude.ai); no API keys.
#   scripts/uat-clis.sh            # or: make uat-clis
#   KEEP=1 scripts/uat-clis.sh     # keep containers + scratch for debugging
# Results table: $UAT_CLI_RESULTS (default: printed scratch path). See test/uat/CLI-REPORT.md.
set -euo pipefail
cd "$(dirname "$0")/.."
sweep() {
  [ "${KEEP:-}" = 1 ] && return
  for c in $(docker ps -aq --filter label=halos-uat-clis); do docker rm -f "$c" >/dev/null 2>&1 || true; done
  for n in $(docker network ls -q --filter label=halos-uat-clis); do docker network rm "$n" >/dev/null 2>&1 || true; done
}
trap sweep EXIT INT TERM
start=$(date +%s)
UAT_CLI_RESULTS=${UAT_CLI_RESULTS:-$PWD/test/uat/cli-results.md} go test -tags uat ./test/uat/ -run TestCLIs -v -count=1 -timeout 45m "$@"
echo "uat-clis: $(( $(date +%s) - start ))s"
