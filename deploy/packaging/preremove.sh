#!/bin/sh
# Stop halod on removal, not on upgrade (deb: "remove"; rpm: $1 = 0).
set -e
case "${1:-}" in
  remove|0)
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
      systemctl disable --now halod || true
    fi
    ;;
esac
