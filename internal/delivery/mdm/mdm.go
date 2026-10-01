// Package mdm exports a release for MDM delivery: a .mobileconfig (Jamf,
// Kandji) carrying Claude Code managed settings under com.anthropic.claudecode,
// an Intune PowerShell script writing HKLM\SOFTWARE\Policies\ClaudeCode, and
// halod bootstrap scripts. Only the claude-code harness has an MDM channel.
package mdm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"howett.net/plist"

	"github.com/halos-dev/halos/internal/release"
)

const (
	PlistDomain = "com.anthropic.claudecode"
	RegistryKey = `HKLM:\SOFTWARE\Policies\ClaudeCode`
	harnessName = "claude-code"
)

// HalodOptions parameterises the halod bootstrap. All fields are required and are
// validated before any script is emitted.
type HalodOptions struct {
	Registry    string
	Org         string // must equal the org in the signed release; written as org:
	Ring        string
	PubKeyPEM   string            // release ed25519 public key (PKIX PEM), embedded inline; never downloaded
	DownloadURL string            // https only; {os}/{arch} substituted
	HalodSHA256 map[string]string // "<os>/<arch>" -> hex sha256 of the halod binary, e.g. "darwin/arm64"
}

// Verifier authenticates a release (signature check against the trust root).
// Exporters call it before emitting anything; callers must not pass a
// release that has not been verified by a real verifier.
type Verifier func(*release.Release) error

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	regRe    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?(/[a-zA-Z0-9][a-zA-Z0-9._-]*)+$`)
	urlRe    = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%+@,=&?{}-]*)*$`)
	shaRe    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ValidateName checks a ring name: ^[a-z0-9][a-z0-9._-]{0,62}$.
func ValidateName(s string) error {
	if !nameRe.MatchString(s) {
		return fmt.Errorf("mdm: invalid name %q", s)
	}
	return nil
}

// validate checks every templated value and returns the canonical PEM.
func (o HalodOptions) validate(oses ...string) (pemText string, err error) {
	if err := ValidateName(o.Ring); err != nil {
		return "", fmt.Errorf("ring: %w", err)
	}
	if err := ValidateName(o.Org); err != nil {
		return "", fmt.Errorf("org: %w", err)
	}
	if !regRe.MatchString(o.Registry) || len(o.Registry) > 255 {
		return "", fmt.Errorf("mdm: invalid registry %q", o.Registry)
	}
	probe := strings.NewReplacer("{os}", "x", "{arch}", "y").Replace(o.DownloadURL)
	if u, perr := url.Parse(probe); perr != nil || u.Scheme != "https" || u.Host == "" || !urlRe.MatchString(o.DownloadURL) {
		return "", fmt.Errorf("mdm: download URL must be a plain https URL, got %q", o.DownloadURL)
	}
	blk, rest := pem.Decode([]byte(o.PubKeyPEM))
	if blk == nil || blk.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return "", fmt.Errorf("mdm: PubKeyPEM must be exactly one PUBLIC KEY PEM block")
	}
	k, perr := x509.ParsePKIXPublicKey(blk.Bytes)
	if _, ok := k.(ed25519.PublicKey); perr != nil || !ok {
		return "", fmt.Errorf("mdm: PubKeyPEM is not an ed25519 public key")
	}
	for _, os := range oses {
		for _, arch := range []string{"amd64", "arm64"} {
			if h := o.HalodSHA256[os+"/"+arch]; !shaRe.MatchString(h) {
				return "", fmt.Errorf("mdm: HalodSHA256[%q] missing or not 64 hex chars", os+"/"+arch)
			}
		}
	}
	return string(pem.EncodeToMemory(blk)), nil
}

// shq single-quotes s for bash. psq single-quotes s for PowerShell.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
func psq(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func checkRelease(rel *release.Release, v Verifier) error {
	if v == nil {
		return fmt.Errorf("mdm: a release Verifier is required")
	}
	if err := v(rel); err != nil {
		return fmt.Errorf("mdm: refusing unverified release: %w", err)
	}
	if !digestRe.MatchString(rel.Digest) {
		return fmt.Errorf("mdm: invalid release digest %q", rel.Digest)
	}
	return ValidateName(rel.Manifest.Ring)
}

// settings returns the managed-settings.json bytes for os from the release.
func settings(rel *release.Release, os string) ([]byte, error) {
	he, ok := rel.Manifest.Harnesses[harnessName]
	if !ok {
		return nil, fmt.Errorf("mdm: release has no %s harness", harnessName)
	}
	for _, f := range he.Files[os] {
		if strings.HasSuffix(strings.ReplaceAll(f.Path, `\`, "/"), "/managed-settings.json") {
			b, ok := rel.Content(f)
			if !ok {
				return nil, fmt.Errorf("mdm: blob for %s missing", f.Path)
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("mdm: no managed-settings.json for %s in release", os)
}

// ExportJamf returns a .mobileconfig with the darwin managed settings as a
// managed-preferences payload. Kandji consumes the same file.
// The release must be verified: v is called first and a nil v is an error.
func ExportJamf(rel *release.Release, v Verifier) ([]byte, error) {
	if err := checkRelease(rel, v); err != nil {
		return nil, err
	}
	raw, err := settings(rel, "darwin")
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var s map[string]any
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("mdm: parse managed settings: %w", err)
	}
	payload := normalize(s).(map[string]any)
	sum := sha256.Sum256([]byte(rel.Digest))
	payload["PayloadType"] = PlistDomain
	payload["PayloadVersion"] = 1
	payload["PayloadIdentifier"] = "dev.halos.claudecode." + rel.Manifest.Ring
	payload["PayloadUUID"] = uuid(sum[:16], 0)
	payload["PayloadDisplayName"] = "Claude Code managed settings"
	root := map[string]any{
		"PayloadContent":      []any{payload},
		"PayloadType":         "Configuration",
		"PayloadVersion":      1,
		"PayloadIdentifier":   "dev.halos.release." + rel.Manifest.Ring,
		"PayloadUUID":         uuid(sum[16:], 1),
		"PayloadDisplayName":  "Halos " + rel.Manifest.Ring,
		"PayloadDescription":  "Halos release " + rel.Digest,
		"PayloadOrganization": rel.Manifest.Org,
		"PayloadScope":        "System",
	}
	return plist.MarshalIndent(root, plist.XMLFormat, "  ") // map keys are emitted sorted => deterministic
}

// normalize converts json.Number to int64/float64 so plist emits integer/real.
func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = normalize(e)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = normalize(e)
		}
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, _ := t.Float64()
		return f
	}
	return v
}

// uuid formats 16 bytes as a v4-shaped UUID; salt keeps the two IDs distinct.
func uuid(b []byte, salt byte) string {
	u := append([]byte(nil), b...)
	u[0] ^= salt
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	return fmt.Sprintf("%X-%X-%X-%X-%X", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// JamfPostinstall is a pkg/Jamf postinstall script that installs halod (sha256
// pinned) under /Library/Halos (root:wheel), the inline verification key
// and a launchd daemon, then runs the first apply. Packaging in cmd/halod must
// use the same paths.
func JamfPostinstall(o HalodOptions) ([]byte, error) {
	pub, err := o.validate("darwin")
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`#!/bin/bash
set -euo pipefail
case "$(uname -m)" in
  arm64) arch=arm64; want=%[1]s ;;
  *) arch=amd64; want=%[2]s ;;
esac
url=%[3]s; url="${url//\{os\}/darwin}"; url="${url//\{arch\}/$arch}"
base=/Library/Halos
install -d -o 0 -g 0 -m 0755 "$base" "$base/bin" "$base/etc" "$base/var"
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp"
echo "$want  $tmp" | shasum -a 256 -c - >/dev/null || { echo "halod sha256 mismatch" >&2; exit 1; }
install -o 0 -g 0 -m 0755 "$tmp" "$base/bin/halod"
install -o 0 -g 0 -m 0644 /dev/null "$base/etc/release.pub"
cat > "$base/etc/release.pub" <<'PUB'
%[4]sPUB
install -o 0 -g 0 -m 0644 /dev/null "$base/etc/halod.yaml"
cat > "$base/etc/halod.yaml" <<'CFG'
registry: %[5]s
org: %[7]s
ring: %[6]s
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
`, shq(strings.ToLower(o.HalodSHA256["darwin/arm64"])), shq(strings.ToLower(o.HalodSHA256["darwin/amd64"])), shq(o.DownloadURL), pub, o.Registry, o.Ring, o.Org)), nil
}

// ExportIntune returns a PowerShell script that writes the Windows managed
// settings JSON to HKLM\SOFTWARE\Policies\ClaudeCode (value Settings, REG_SZ)
// and installs halod as a SYSTEM startup task. Binary, config and key live under
// Program Files (admin-only), including state (var\state.json). The vendor-mandated
// ProgramData dirs (OpenAI\Codex, gemini-cli) are recreated with an explicit
// ACL if not owned by SYSTEM/Administrators.
// The release must be verified: v is called first and a nil v is an error.
func ExportIntune(rel *release.Release, o HalodOptions, v Verifier) ([]byte, error) {
	if err := checkRelease(rel, v); err != nil {
		return nil, err
	}
	pub, err := o.validate("windows")
	if err != nil {
		return nil, err
	}
	raw, err := settings(rel, "windows")
	if err != nil {
		return nil, err
	}
	var jv any
	if err := json.Unmarshal(raw, &jv); err != nil {
		return nil, fmt.Errorf("mdm: parse managed settings: %w", err)
	}
	compact, _ := json.Marshal(jv) // sorted keys, one line: safe inside a PS single-quoted here-string
	if bytes.Contains(compact, []byte("\n'@")) || bytes.ContainsAny(compact, "\r\n") {
		return nil, fmt.Errorf("mdm: settings contain here-string terminator")
	}
	var b strings.Builder
	fmt.Fprintf(&b, `# Halos release %s (ring %s). Generated; do not edit.
$ErrorActionPreference = 'Stop'
$key = %s
New-Item -Path $key -Force | Out-Null
$json = @'
%s
'@
New-ItemProperty -Path $key -Name 'Settings' -Value $json -PropertyType String -Force | Out-Null

$dir = 'C:\Program Files\Halos'
# Standard users can create dirs under ProgramData: never trust a pre-existing one we do not own.
# halod state lives under Program Files; the vendor CLIs' mandated system-config dirs are locked here.
function Lock-Dir($d) {
  if (Test-Path -LiteralPath $d) {
    $owner = (Get-Acl -LiteralPath $d).GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne 'S-1-5-18' -and $owner -ne 'S-1-5-32-544') { Remove-Item -LiteralPath $d -Recurse -Force }
  }
  New-Item -ItemType Directory -Force -Path $d | Out-Null
  icacls $d /setowner '*S-1-5-32-544' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls setowner failed: $d" }
  icacls $d /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "icacls failed: $d" }
}
Lock-Dir 'C:\ProgramData\OpenAI\Codex'
Lock-Dir 'C:\ProgramData\gemini-cli'
foreach ($d in @($dir, "$dir\bin", "$dir\etc", "$dir\var")) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
icacls $dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls failed' }
$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$want = @{ 'amd64' = %s; 'arm64' = %s }[$arch]
$url = %s.Replace('{os}', 'windows').Replace('{arch}', $arch)
$tmp = Join-Path "$dir\bin" 'halod.exe.download'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp
$got = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash
if ($got -ne $want) { Remove-Item -LiteralPath $tmp -Force; throw "halod sha256 mismatch: $got" }
Move-Item -LiteralPath $tmp -Destination "$dir\bin\halod.exe" -Force
@'
%s'@ | Set-Content -Encoding ascii "$dir\etc\release.pub"
@'
registry: %s
org: %s
ring: %s
pubkey: C:\Program Files\Halos\etc\release.pub
os: windows
'@ | Set-Content -Encoding ascii "$dir\etc\halod.yaml"
$action = New-ScheduledTaskAction -Execute "$dir\bin\halod.exe" -Argument ('run --config "' + $dir + '\etc\halod.yaml" --state "' + $dir + '\var\state.json"')
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'Halos' -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName 'Halos'
`, rel.Digest, rel.Manifest.Ring, psq(RegistryKey), compact,
		psq(o.HalodSHA256["windows/amd64"]), psq(o.HalodSHA256["windows/arm64"]), psq(o.DownloadURL), pub, o.Registry, o.Org, o.Ring)
	return []byte(b.String()), nil
}
