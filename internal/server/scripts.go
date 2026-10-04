package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Both scripts refuse to install halod unless its SHA-256 matches the value pinned in server config.

func (s *Server) pins() []string {
	keys := make([]string, 0, len(s.cfg.Portal.HalodSHA256))
	for k := range s.cfg.Portal.HalodSHA256 {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (s *Server) enrollSh(w http.ResponseWriter, r *http.Request) {
	pc, base := s.cfg.Portal, s.baseURL(r)
	if base == "" || pc.HalodURL == "" || len(pc.HalodSHA256) == 0 {
		apiErr(w, http.StatusNotFound, "enrollment not configured")
		return
	}
	var cases strings.Builder
	for _, k := range s.pins() {
		fmt.Fprintf(&cases, "  %s) WANT=%s ;;\n", k, pc.HalodSHA256[k])
	}
	dl := strings.NewReplacer("{os}", "$OS", "{arch}", "$ARCH").Replace(pc.HalodURL)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	//nolint:gosec // served as text/x-shellscript from operator config, not HTML
	fmt.Fprintf(w, `#!/bin/sh
# Halos laptop enrollment. Usage: enroll.sh <token>   (token comes from the portal)
set -eu
TOKEN="${1:?usage: enroll.sh <token>}"
SERVER="%[1]s"
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in x86_64|amd64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) echo "unsupported arch" >&2; exit 1 ;; esac
case "$OS-$ARCH" in
%[2]s  *) echo "no pinned checksum for $OS-$ARCH; refusing to install" >&2; exit 1 ;;
esac
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO=sudo
# Root-owned, non-group/other-writable locations only: halod refuses to start otherwise.
case "$OS" in
  darwin) BIN=/Library/Halos/bin/halod; ETC=/Library/Halos/etc; VAR=/Library/Halos/var ;;
  *) BIN=/usr/local/lib/halos/halod; ETC=/etc/halos; VAR=/var/lib/halos ;;
esac
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
curl -fsSL "%[3]s" -o "$TMP/halod"
if command -v sha256sum >/dev/null 2>&1; then GOT=$(sha256sum "$TMP/halod" | cut -d' ' -f1); else GOT=$(shasum -a 256 "$TMP/halod" | cut -d' ' -f1); fi
[ "$GOT" = "$WANT" ] || { echo "halod checksum mismatch; aborting" >&2; exit 1; }
$SUDO install -d -m 0755 -o 0 -g 0 "$(dirname "$BIN")" "$ETC"
$SUDO install -d -m 0700 -o 0 -g 0 "$VAR"
$SUDO install -m 0755 -o 0 -g 0 "$TMP/halod" "$BIN"
curl -fsSL -X POST -H 'Content-Type: application/json' -d "{\"token\":\"$TOKEN\",\"os\":\"$OS\"}" "$SERVER/api/v1/enroll" -o "$TMP/halod.yaml"
curl -fsSL "$SERVER/enroll/release.pub" -o "$TMP/release.pub"
$SUDO install -m 0600 -o 0 -g 0 "$TMP/halod.yaml" "$ETC/halod.yaml"
$SUDO install -m 0644 -o 0 -g 0 "$TMP/release.pub" "$ETC/release.pub"
if grep -q '^killSwitch:' "$TMP/halod.yaml"; then
  curl -fsSL "$SERVER/enroll/killswitch.pub" -o "$TMP/killswitch.pub"
  $SUDO install -m 0644 -o 0 -g 0 "$TMP/killswitch.pub" "$ETC/killswitch.pub"
fi
echo "halod installed at $BIN and this machine is enrolled. Config: $ETC/halod.yaml"
# Start halod as a service so the first check-in happens now and keeps happening.
# Without launchd/systemd (containers, unusual distros) say exactly what to run instead.
if $SUDO "$BIN" service install --start >/dev/null 2>&1; then
  echo "halod is running. It installs your pinned CLIs and applies your ring's policy;"
  echo "this device appears on $SERVER within a minute. Check anytime: sudo $BIN status"
else
  echo "halod is not running yet (no launchd/systemd here). Run it yourself:"
  echo "  sudo $BIN once                    # apply your ring's policy now"
  echo "  sudo $BIN service install --start   # keep it applied"
fi
`, base, cases.String(), dl)
}

func (s *Server) enrollPs1(w http.ResponseWriter, r *http.Request) {
	pc, base := s.cfg.Portal, s.baseURL(r)
	if base == "" || pc.HalodURL == "" || len(pc.HalodSHA256) == 0 {
		apiErr(w, http.StatusNotFound, "enrollment not configured")
		return
	}
	var tbl strings.Builder
	for _, k := range s.pins() {
		fmt.Fprintf(&tbl, "  '%s' = '%s'\n", k, pc.HalodSHA256[k])
	}
	dl := strings.NewReplacer("{os}", "windows", "{arch}", "$Arch").Replace(pc.HalodURL)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	//nolint:gosec // served as text/plain from operator config, not HTML
	fmt.Fprintf(w, `# Halos laptop enrollment (Windows). Run elevated.
param([Parameter(Mandatory)][string]$Token)
$ErrorActionPreference = 'Stop'
$Server = '%[1]s'
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$Pins = @{
%[2]s}
$Want = $Pins["windows-$Arch"]
if (-not $Want) { throw "no pinned checksum for windows-$Arch; refusing to install" }
$Tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([guid]::NewGuid()))
try {
  $Exe = Join-Path $Tmp 'halod.exe'
  Invoke-WebRequest -UseBasicParsing "%[3]s" -OutFile $Exe
  if ((Get-FileHash $Exe -Algorithm SHA256).Hash.ToLower() -ne $Want) { throw 'halod checksum mismatch; aborting' }
  # Everything under Program Files (the shared app-data dir lets any user pre-create
  # the directory). etc/ and var/ hold the device token and state: SYSTEM and
  # Administrators only, inheritance removed, so Users cannot even read them.
  $Dir = Join-Path $env:ProgramFiles 'Halos'; $Etc = Join-Path $Dir 'etc'; $Var = Join-Path $Dir 'var'
  New-Item -ItemType Directory -Force -Path $Dir, $Etc, $Var | Out-Null
  foreach ($D in @($Etc, $Var)) {
    & icacls $D /setowner '*S-1-5-32-544' | Out-Null
    & icacls $D /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls hardening failed on $D" }
  }
  Copy-Item $Exe (Join-Path $Dir 'halod.exe') -Force
  $Body = @{ token = $Token; os = 'windows' } | ConvertTo-Json
  Invoke-RestMethod -Method Post -Uri "$Server/api/v1/enroll" -ContentType 'application/json' -Body $Body -OutFile (Join-Path $Etc 'halod.yaml')
  Invoke-WebRequest -UseBasicParsing "$Server/enroll/release.pub" -OutFile (Join-Path $Etc 'release.pub')
  if (Select-String -Path (Join-Path $Etc 'halod.yaml') -Pattern '^killSwitch:' -Quiet) {
    Invoke-WebRequest -UseBasicParsing "$Server/enroll/killswitch.pub" -OutFile (Join-Path $Etc 'killswitch.pub')
  }
  Write-Host "halod installed and this machine is enrolled. Config: $Etc\halod.yaml"
  # Start halod as a scheduled task so the first check-in happens now and keeps happening.
  & (Join-Path $Dir 'halod.exe') service install --start | Out-Null
  if ($LASTEXITCODE -eq 0) {
    Write-Host "halod is running. It installs your pinned CLIs and applies your ring's policy;"
    Write-Host "this device appears on $Server within a minute. Check anytime: halod status"
  } else {
    Write-Host "halod is not running yet. Run it yourself (elevated): halod once; halod service install --start"
  }
} finally { Remove-Item -Recurse -Force $Tmp }
`, base, tbl.String(), dl)
}
