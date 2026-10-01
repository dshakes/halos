#!/bin/sh
# halod package post-install. Never enrolls, enables or starts the agent: that
# needs an operator-supplied /etc/halos/halod.yaml and release public key.
set -e
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
echo "halod installed but NOT enabled. Write /etc/halos/halod.yaml (root-owned), then:"
echo "  systemctl enable --now halod"
