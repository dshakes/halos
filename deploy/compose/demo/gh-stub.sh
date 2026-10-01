#!/bin/sh
# DEV ONLY stand-in for the GitHub CLI inside the demo halo-server image. The demo has no
# GitHub: a console "Propose change" pushes a real branch to the local policy remote
# (/repo/remote.git) and this prints where it landed instead of a PR URL.
if [ "${1:-} ${2:-}" != "pr create" ]; then
  echo "gh stub: only 'pr create' is supported in the demo" >&2
  exit 1
fi
head=""
while [ $# -gt 0 ]; do
  [ "$1" = "--head" ] && head=${2:-}
  shift
done
echo "local branch $head in the demo policy remote (no GitHub PR)"
