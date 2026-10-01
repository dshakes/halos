# Halos: label this CLI's telemetry with the release (login shells).
codex() { OTEL_RESOURCE_ATTRIBUTES='cost-center=a%2Fb,halo.harness=codex,halo.release=sha256%3Aabc,halo.ring=canary,team=platform%20eng' command codex "$@"; }
[ -z "${BASH_VERSION:-}" ] || export -f codex
