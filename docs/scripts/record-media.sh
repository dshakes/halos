#!/usr/bin/env bash
# Records the site's terminal clips with vhs from the real halo CLI, in the
# Eclipse palette, and encodes each as WebM + MP4 (landing page), GIF (README)
# and a JPEG poster. Output: docs/public/media/ (committed). Never hand-edit.
#
# Needs Go, Docker (a throwaway registry:2 on 127.0.0.1:5056 so `halo upgrade
# start` can read the GA ring's signed pointer), vhs (with ttyd) and ffmpeg.
# The console walkthrough is recorded separately by record-console.sh.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
out=$root/docs/public/media
tmp=$(mktemp -d)
trap 'docker rm -f halos-media-reg >/dev/null 2>&1 || true; rm -rf "$tmp"' EXIT
mkdir -p "$out" "$tmp/bin"
claude=${CLAUDE_VERSION:-2.1.286} # matches docs/src/data/terminal.json

(cd "$root" && go build -o "$tmp/bin/halo" ./cmd/halo)
docker run -d --name halos-media-reg -p 127.0.0.1:5056:5000 registry:2 >/dev/null
export HALO_REGISTRY=127.0.0.1:5056/acme/halos HALO_KEY=$tmp/k/halo.key XDG_STATE_HOME=$tmp/state
"$tmp/bin/halo" keys generate --out "$tmp/k" >/dev/null

# Hidden setup each tape sources: the real binary first on PATH and a corona prompt.
cat > "$tmp/env.sh" <<EOF
export PATH="$tmp/bin:\$PATH" HALO_REGISTRY=$HALO_REGISTRY HALO_KEY=$HALO_KEY XDG_STATE_HOME=$XDG_STATE_HOME
export PS1='\[\e[38;2;246;196;83m\]acme\[\e[38;2;255;106;61m\] ❯ \[\e[0m\]'
EOF

# Pre-stage: a fresh repo whose GA ring is published (the upgrade's baseline),
# and a copy of the example repo for the toggle and gateway clips.
mkdir -p "$tmp/fresh" "$tmp/up"
(cd "$tmp/up" && halo=$tmp/bin/halo && $halo init --org acme >/dev/null &&
  $halo release publish --ring ring3-ga --release-version 1.0.0 --plain-http --registry "$HALO_REGISTRY" --key "$HALO_KEY" >/dev/null)
cp -R "$root/examples/acme-corp" "$tmp/acme"

theme='{"name":"Eclipse","background":"#0c0c10","foreground":"#f4f1ea","cursor":"#ffb547","selection":"#3a2410",
"black":"#18181e","red":"#ff7a7a","green":"#6ee7a8","yellow":"#f6c453","blue":"#8ea2ff","magenta":"#ff9d7a","cyan":"#ffd48a","white":"#e3ded4",
"brightBlack":"#8e897f","brightRed":"#ff9a9a","brightGreen":"#8ff0bd","brightYellow":"#ffd48a","brightBlue":"#aebcff","brightMagenta":"#ffb59a","brightCyan":"#ffe6a8","brightWhite":"#ffffff"}'

# tape NAME DIR WIDTH HEIGHT FONTSIZE, then "cmd|pause" lines on stdin.
tape() {
  local name=$1 dir=$2 w=$3 h=$4 fs=$5
  {
    printf 'Output "%s/%s.mp4"\nSet Shell bash\nSet Theme %s\n' "$tmp" "$name" "$(printf '%s' "$theme" | tr -d '\n')"
    printf 'Set FontFamily "Menlo"\nSet FontSize %s\nSet Width %s\nSet Height %s\nSet Padding 28\n' "$fs" "$w" "$h"
    printf 'Set WindowBar Colorful\nSet WindowBarSize 40\nSet BorderRadius 14\nSet TypingSpeed 38ms\nSet Framerate 24\n'
    printf 'Hide\nType "source %s/env.sh && cd %s && clear"\nEnter\nSleep 500ms\nShow\nSleep 600ms\n' "$tmp" "$dir"
    while IFS='|' read -r cmd pause; do
      printf 'Type "%s"\nSleep 450ms\nEnter\nSleep %s\n' "$cmd" "$pause"
    done
  } > "$tmp/$name.tape"
  vhs "$tmp/$name.tape" >/dev/null
}

tape init "$tmp/fresh" 1360 400 15 <<'EOF'
halo init --org acme|1800ms
halo validate --policy-dir .|3s
EOF
tape upgrade "$tmp/up" 1360 500 14 <<EOF
halo upgrade start claude-code $claude --plain-http|5s
EOF
tape simulate "$tmp/up" 1360 420 14 <<EOF
halo rollout simulate claude-code-$claude --scenario regression|5s
EOF
tape toggle "$tmp/acme" 1360 520 15 <<'EOF'
halo toggle eval --user alice@acme.com --groups ai-platform|2500ms
halo toggle eval --user alice@acme.com --groups ai-platform --killed sonnet-next-route|4s
EOF
tape gateway "$tmp/acme" 1900 400 13 <<'EOF'
halo gateway routes --user alice@acme.com|5s
EOF

# Encode: VP9 WebM and H.264 MP4 for the page, a palette GIF for the README,
# and a poster from the final frame (what a reduced-motion visitor sees).
for n in init upgrade simulate toggle gateway; do
  src=$tmp/$n.mp4 w=1280
  [ $n = gateway ] && w=1600 # widest table; keep it legible
  ffmpeg -loglevel error -y -i "$src" -an -c:v libvpx-vp9 -b:v 0 -crf 40 -row-mt 1 -vf scale=$w:-2 "$out/$n.webm"
  ffmpeg -loglevel error -y -i "$src" -an -c:v libx264 -crf 30 -preset slow -pix_fmt yuv420p -movflags +faststart -vf scale=$w:-2 "$out/$n.mp4"
  ffmpeg -loglevel error -y -i "$src" -vf "fps=10,scale=1100:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=48:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle" "$out/$n.gif"
  ffmpeg -loglevel error -y -sseof -0.3 -i "$src" -frames:v 1 -vf scale=$w:-2 -q:v 4 "$out/$n.jpg"
done
ls -la "$out"
