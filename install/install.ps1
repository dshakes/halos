<#
.SYNOPSIS
  Halos installer for Windows (run from an elevated PowerShell).
.DESCRIPTION
  Installs halo (and halod with -WithAgent) to $env:ProgramFiles\Halos. Verifies
  every archive against checksums.txt, and checksums.txt against its cosign
  signature when cosign is on PATH (otherwise warns and trusts the sha256 only).
  Binaries are not Authenticode-signed. The directory is limited to SYSTEM and
  Administrators (write) plus Users (read/execute), matching halod's owner check.
#>
[CmdletBinding()]
param(
  [string]$Version = $env:HALOS_VERSION,
  [switch]$WithAgent
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Repo = 'dshakes/halos'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'install.ps1: run from an elevated (Administrator) PowerShell'
}
switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { $arch = 'amd64' }
  'ARM64' { $arch = 'arm64' }
  default { throw "install.ps1: unsupported architecture $env:PROCESSOR_ARCHITECTURE" }
}

if (-not $Version) {
  Write-Warning 'no -Version given; resolving latest (pin a version in automation)'
  $Version = (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest").tag_name
}
if ($Version -notmatch '^v?\d+\.\d+\.\d+([.+-][A-Za-z0-9.+-]+)?$') { throw "install.ps1: bad version $Version" }
if (-not $Version.StartsWith('v')) { $Version = "v$Version" }
$num = $Version.Substring(1)
$base = "https://github.com/$Repo/releases/download/$Version"

$tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  function Get-Asset([string]$name) {
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$name" -OutFile (Join-Path $tmp $name)
  }
  Get-Asset 'checksums.txt'
  if (Get-Command cosign -ErrorAction SilentlyContinue) {
    Get-Asset 'checksums.txt.sig'
    Get-Asset 'checksums.txt.pem'
    & cosign verify-blob `
      --certificate-identity "https://github.com/$Repo/.github/workflows/release.yml@refs/tags/$Version" `
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' `
      --signature (Join-Path $tmp 'checksums.txt.sig') --certificate (Join-Path $tmp 'checksums.txt.pem') `
      (Join-Path $tmp 'checksums.txt') *> $null
    if ($LASTEXITCODE -ne 0) { throw 'install.ps1: cosign signature verification FAILED for checksums.txt' }
    Write-Host 'cosign signature verified'
  } else {
    Write-Warning 'cosign not found; the signature was NOT verified.'
    Write-Warning 'Trusting the sha256 checksums downloaded from the same origin.'
  }

  $dest = Join-Path $env:ProgramFiles 'Halos'
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  # SYSTEM + Administrators full control, Users read/execute; no inherited ACEs.
  & icacls $dest /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "install.ps1: icacls failed on $dest" }
  # halod checks the owner SID: make it Administrators, not whoever created the dir.
  & icacls $dest /setowner '*S-1-5-32-544' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "install.ps1: icacls /setowner failed on $dest" }

  $bins = @('halo'); if ($WithAgent) { $bins += 'halod' }
  foreach ($b in $bins) {
    $file = "${b}_${num}_windows_${arch}.zip"
    Get-Asset $file
    $line = Get-Content (Join-Path $tmp 'checksums.txt') | Where-Object { ($_ -split '\s+')[1] -eq $file }
    if (-not $line) { throw "install.ps1: $file is not listed in checksums.txt" }
    $want = ($line -split '\s+')[0]
    $got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $file)).Hash
    if ($got -ne $want.ToUpperInvariant()) { throw "install.ps1: sha256 mismatch for $file" }
    $x = Join-Path $tmp "x-$b"
    Expand-Archive -Path (Join-Path $tmp $file) -DestinationPath $x
    Copy-Item -Force (Join-Path $x "$b.exe") (Join-Path $dest "$b.exe")
    Write-Host "installed $(Join-Path $dest "$b.exe") ($Version)"
  }

  $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  if (($machinePath -split ';') -notcontains $dest) {
    [Environment]::SetEnvironmentVariable('Path', "$machinePath;$dest", 'Machine')
    Write-Host "added $dest to the machine PATH (open a new shell)"
  }
  if ($WithAgent) { Write-Host 'halod is not enrolled or started; see "halod service install --help"' }
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
