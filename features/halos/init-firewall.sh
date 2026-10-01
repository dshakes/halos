#!/usr/bin/env bash
# Egress allowlist (gateway + registry only), same approach as
# anthropics/claude-code .devcontainer/init-firewall.sh: ipset of resolved IPs,
# default-DROP (IPv4 and IPv6), allow loopback/established and DNS to the
# container's own resolvers only. Runs at container start as the feature
# `entrypoint` (needs root + NET_ADMIN/NET_RAW; devcontainer-feature.json capAdd).
# Fails closed: policies go to DROP before anything else is parsed or resolved,
# every failing exit (explicit, `set -e`, unset var) goes through fail() or the
# EXIT trap so the status file is always written, and egress stays blocked. A background loop re-resolves every
# HALOS_FW_REFRESH seconds (default 300) and swaps the ipsets atomically.
set -Eeuo pipefail

HOSTS_FILE=/etc/halos/firewall-hosts
REFRESH="${HALOS_FW_REFRESH:-300}"
[ -f "$HOSTS_FILE" ] || exit 0 # firewall option not enabled
STATUS_FILE=/run/halos-firewall.status
FAILED=0

# fail <msg>: record status, print a prominent banner, exit non-zero (fail closed).
fail() {
  FAILED=1
  printf 'FAILED: %s\n' "$*" > "$STATUS_FILE" 2>/dev/null || true
  {
    echo "################################################################"
    echo "# HALOS FIREWALL FAILURE: $*"
    echo "# The firewall did NOT come up cleanly; treat egress as unverified."
    echo "# Status: $STATUS_FILE"
    echo "################################################################"
  } >&2
  exit 1
}

on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ] && [ "$FAILED" = 0 ]; then
    printf 'FAILED: exited with status %s\n' "$rc" > "$STATUS_FILE" 2>/dev/null || true
  fi
}

# Main run only (not the refresh loop): any unexpected error or non-zero exit
# (set -e, unset variable, explicit exit) still records FAILED.
if [ "${1:-}" != "--refresh-loop" ]; then
  trap 'fail "unexpected error (line $LINENO): $BASH_COMMAND"' ERR
  trap on_exit EXIT
fi

if [ "$(id -u)" -ne 0 ]; then exec sudo -n "$0" "$@"; fi

hosts=$(cat "$HOSTS_FILE")
# The ghcr blob host serves layer downloads; without it pulls fail.
case " $hosts " in *" ghcr.io "*) hosts="$hosts pkg-containers.githubusercontent.com" ;; esac

resolve() { # resolve <set4> <set6>: fill fresh sets with A/AAAA of every host
  local h ip
  for h in $hosts; do
    h="${h%%:*}"
    local got=0
    for ip in $(dig +short A "$h" | grep -E '^[0-9.]+$' || true); do ipset add -exist "$1" "$ip" && got=1; done
    for ip in $(dig +short AAAA "$h" | grep -E '^[0-9a-fA-F:]+$' || true); do ipset add -exist "$2" "$ip" && got=1; done
    [ "$got" = 1 ] || { echo "firewall: cannot resolve $h" >&2; return 1; }
  done
}

refresh() {
  ipset create -exist halo-allowed4-new hash:net family inet
  ipset create -exist halo-allowed6-new hash:net family inet6
  ipset flush halo-allowed4-new; ipset flush halo-allowed6-new
  if resolve halo-allowed4-new halo-allowed6-new; then
    ipset swap halo-allowed4 halo-allowed4-new; ipset swap halo-allowed6 halo-allowed6-new
  else
    echo "firewall: refresh failed, keeping previous allowlist" >&2
  fi
  ipset destroy halo-allowed4-new 2>/dev/null || true; ipset destroy halo-allowed6-new 2>/dev/null || true
}

if [ "${1:-}" = "--refresh-loop" ]; then
  while sleep "$REFRESH"; do refresh || true; done
fi

# Tools are installed at build time by install.sh; never install at runtime.
for t in iptables ipset dig curl; do
  command -v "$t" >/dev/null || fail "required tool '$t' missing (install.sh installs it at build time; rebuild the image with firewall=true). Not installing at runtime."
done

have6=1
command -v ip6tables >/dev/null && ip6tables -L -n >/dev/null 2>&1 || have6=0

# Default DROP first (fail closed), then open only what is needed.
for ipt in iptables ip6tables; do
  [ "$ipt" = ip6tables ] && [ "$have6" = 0 ] && continue
  "$ipt" -P INPUT DROP; "$ipt" -P FORWARD DROP; "$ipt" -P OUTPUT DROP
  "$ipt" -F; "$ipt" -X
  "$ipt" -A INPUT  -i lo -j ACCEPT
  "$ipt" -A OUTPUT -o lo -j ACCEPT
  "$ipt" -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT
  "$ipt" -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
done
if [ "$have6" = 0 ]; then
  # No ip6tables: fail closed by turning IPv6 off entirely.
  sysctl -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 >/dev/null \
    || fail "cannot restrict or disable IPv6"
fi
for h in $hosts; do
  [[ "$h" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]*$ ]] || fail "bad host in $HOSTS_FILE: $h"
done

# DNS only to the resolvers in resolv.conf.
resolvers=$(awk '$1=="nameserver"{print $2}' /etc/resolv.conf)
[ -n "$resolvers" ] || fail "no nameserver in /etc/resolv.conf (egress stays blocked)"

for r in $resolvers; do
  if [[ "$r" == *:* ]]; then
    [ "$have6" = 1 ] || continue
    ip6tables -A OUTPUT -d "$r" -p udp --dport 53 -j ACCEPT
    ip6tables -A OUTPUT -d "$r" -p tcp --dport 53 -j ACCEPT
  else
    iptables -A OUTPUT -d "$r" -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -d "$r" -p tcp --dport 53 -j ACCEPT
  fi
done

ipset create -exist halo-allowed4 hash:net family inet
ipset create -exist halo-allowed6 hash:net family inet6
iptables -A OUTPUT -m set --match-set halo-allowed4 dst -j ACCEPT
[ "$have6" = 0 ] || ip6tables -A OUTPUT -m set --match-set halo-allowed6 dst -j ACCEPT
iptables -A OUTPUT -j REJECT --reject-with icmp-admin-prohibited

refresh

# Self-check: a non-allowed host must fail, an allowed one must connect.
if curl -s --max-time 5 https://example.com >/dev/null; then
  fail "verification failed, example.com reachable"
fi
first="${hosts%% *}"; first="${first%%:*}"
if ! curl -s --max-time 10 -o /dev/null "https://$first"; then
  fail "verification failed, $first unreachable"
fi
printf 'OK: egress restricted to: %s\n' "$hosts" > "$STATUS_FILE"
echo "firewall: egress restricted to: $hosts"

# Background refresh; the entrypoint must return so the container can start.
nohup "$0" --refresh-loop >/dev/null 2>&1 &
