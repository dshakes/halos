#!/usr/bin/env bash
# release-notes.sh vX.Y.Z[-rc.N] [CHANGELOG.md] — print the CHANGELOG section for a tag.
# An rc uses its own `## [X.Y.Z-rc.N]` section if there is one, else the `## [X.Y.Z]`
# section it soaks for. Exits 1 if there is no such section or it is empty.
# Used by scripts/release.sh (preflight) and release.yml (gate + --release-notes).
set -euo pipefail

tag=${1:?usage: release-notes.sh vX.Y.Z[-rc.N] [CHANGELOG.md]}
file=${2:-CHANGELOG.md}
ver=${tag#v}

section() {
  # Lines after `## [<v>]...` up to the next `## ` heading, trimmed of blank edges.
  awk -v h="## [$1]" '
    index($0, h) == 1 { on = 1; next }
    on && /^## / { exit }
    on { buf[++n] = $0 }
    END {
      s = 1; while (s <= n && buf[s] ~ /^[[:space:]]*$/) s++
      e = n; while (e >= s && buf[e] ~ /^[[:space:]]*$/) e--
      for (i = s; i <= e; i++) print buf[i]
    }' "$file"
}

for v in "$ver" "${ver%%-*}"; do
  out=$(section "$v")
  if [ -n "$out" ]; then
    printf '%s\n' "$out"
    [ "$v" = "$ver" ] || echo "release-notes.sh: no [$ver] section; using [$v]" >&2
    exit 0
  fi
done
if [ "$ver" = "${ver%%-*}" ]; then want="[$ver]"; else want="[$ver] or [${ver%%-*}]"; fi
echo "release-notes.sh: $file has no non-empty $want section" >&2
exit 1
