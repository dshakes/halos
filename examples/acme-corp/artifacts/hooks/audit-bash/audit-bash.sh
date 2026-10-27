#!/bin/sh
# PreToolUse hook for Bash: append the command Claude Code is about to run to
# the local audit log, then allow it (exit 0). Delivered by halod as 0644, so
# the profile runs it as `sh <managed dir>/hooks/audit-bash/audit-bash.sh`.
set -eu
log="${ACME_AUDIT_LOG:-/var/tmp/acme-ai-audit.log}"
payload="$(cat)"
printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$payload" >>"$log" 2>/dev/null || true
exit 0
