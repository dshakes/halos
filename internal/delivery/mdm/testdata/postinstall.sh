#!/bin/bash
set -euo pipefail
case "$(uname -m)" in
  arm64) arch=arm64; want='abababababababababababababababababababababababababababababababab' ;;
  *) arch=amd64; want='abababababababababababababababababababababababababababababababab' ;;
esac
url='https://d/{os}-{arch}/halod'; url="${url//\{os\}/darwin}"; url="${url//\{arch\}/$arch}"
base=/Library/Halos
install -d -o 0 -g 0 -m 0755 "$base" "$base/bin" "$base/etc" "$base/var"
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp"
echo "$want  $tmp" | shasum -a 256 -c - >/dev/null || { echo "halod sha256 mismatch" >&2; exit 1; }
install -o 0 -g 0 -m 0755 "$tmp" "$base/bin/halod"
install -o 0 -g 0 -m 0644 /dev/null "$base/etc/release.pub"
cat > "$base/etc/release.pub" <<'PUB'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=
-----END PUBLIC KEY-----
PUB
install -o 0 -g 0 -m 0644 /dev/null "$base/etc/halod.yaml"
cat > "$base/etc/halod.yaml" <<'CFG'
registry: ghcr.io/a/r
org: acme
ring: canary
pubkey: /Library/Halos/etc/release.pub
os: darwin
CFG
cat > /Library/LaunchDaemons/dev.halos.halod.plist <<'PL'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>dev.halos.halod</string>
<key>ProgramArguments</key><array><string>/Library/Halos/bin/halod</string><string>run</string><string>--config</string><string>/Library/Halos/etc/halod.yaml</string><string>--state</string><string>/Library/Halos/var/state.json</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
PL
chown root:wheel /Library/LaunchDaemons/dev.halos.halod.plist; chmod 0644 /Library/LaunchDaemons/dev.halos.halod.plist
launchctl bootstrap system /Library/LaunchDaemons/dev.halos.halod.plist 2>/dev/null || true
