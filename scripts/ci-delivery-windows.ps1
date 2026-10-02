# CI only (windows-latest, elevated runner): the Windows delivery path for real.
#   1. install\install.ps1 -WithAgent against the real release ($env:HALOS_INSTALL_VERSION)
#   2. portal enroll.ps1 against a local halo-server + a signed release in a local registry
#   3. halod once, then `halod service install --start` as the real SYSTEM scheduled task, until
#      managed settings appear in C:\Program Files\ClaudeCode; then `service uninstall`.
#   Every directory halod trusts is checked for the admin-only-write DACL the code claims.
# Not run: Intune, Authenticode, a logged-in interactive user, real vendor CLI installs (--no-artifacts release).
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$version = if ($env:HALOS_INSTALL_VERSION) { $env:HALOS_INSTALL_VERSION } else { 'v0.1.0-rc.2' }
$w = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
$bin = Join-Path $w 'bin'; $srv = Join-Path $w 'srv'
New-Item -ItemType Directory -Force -Path $bin, $srv | Out-Null
$env:XDG_STATE_HOME = Join-Path $w 'state'
$env:GOBIN = $bin
$env:Path = "$bin;$env:Path"
$reg = '127.0.0.1:15055'; $base = 'http://127.0.0.1:18199'
$halos = Join-Path $env:ProgramFiles 'Halos'
$halod = Join-Path $halos 'halod.exe'
$settings = Join-Path $env:ProgramFiles 'ClaudeCode\managed-settings.json'
$procs = @()

function Fail([string]$m) { throw "FAIL: $m" }
function Run([string]$exe, [string[]]$a) {
  & $exe @a
  if ($LASTEXITCODE -ne 0) { Fail "$exe $($a -join ' ') exited $LASTEXITCODE" }
}
function Spawn([string]$name, [string]$exe, [string[]]$a) {
  $script:procs += Start-Process -FilePath $exe -ArgumentList $a -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $w "$name.out") -RedirectStandardError (Join-Path $w "$name.err")
}
function Wait-Until([scriptblock]$cond, [string]$what, [int]$secs = 60) {
  for ($i = 0; $i -lt $secs; $i++) { if (& $cond) { return }; Start-Sleep -Seconds 1 }
  Fail "timed out waiting for $what"
}
$SY = 'S-1-5-18'; $BA = 'S-1-5-32-544'; $BU = 'S-1-5-32-545'
$writeRights = [Security.AccessControl.FileSystemRights]'WriteData,AppendData,WriteExtendedAttributes,WriteAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
# Assert-Acl: owner is SYSTEM/Administrators, only $allowed SIDs appear, and anyone but SYSTEM/Administrators has no write right.
# -Protected also requires inheritance from the parent to be cut (directories halod or the installers create).
function Assert-Acl([string]$path, [string[]]$allowed, [switch]$Protected) {
  $acl = Get-Acl -LiteralPath $path
  $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if ($owner -notin $SY, $BA) { Fail "$path owner is $owner" }
  if ($Protected -and -not $acl.AreAccessRulesProtected) { Fail "$path inherits ACEs from its parent" }
  foreach ($r in $acl.Access) {
    $sid = $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($r.AccessControlType -ne 'Allow') { continue }
    if ($allowed -and $sid -notin $allowed) { Fail "$path grants unexpected $sid ($($r.FileSystemRights))" }
    if ($sid -notin $SY, $BA -and ($r.FileSystemRights -band $writeRights)) { Fail "$path grants $sid write access ($($r.FileSystemRights))" }
  }
  Write-Host "ok: $path owner=$owner acl=[$(($acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }) -join '; ')]"
}

try {
  Write-Host "== install.ps1 -Version $version -WithAgent"
  $threw = $false
  try { & (Join-Path $repo 'install\install.ps1') -Version 'not-a-version' } catch { $threw = $true }
  if (-not $threw) { Fail 'install.ps1 accepted a malformed version' }
  & (Join-Path $repo 'install\install.ps1') -Version $version -WithAgent
  foreach ($b in 'halo.exe', 'halod.exe') { if (-not (Test-Path (Join-Path $halos $b))) { Fail "$b not installed" } }
  Run (Join-Path $halos 'halo.exe') @('version')
  Run (Join-Path $halos 'halod.exe') @('help')
  Assert-Acl $halos @($SY, $BA, $BU) -Protected
  if (([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';') -notcontains $halos) { Fail 'machine PATH lacks the install dir' }

  Write-Host '== build from this checkout'
  Push-Location $repo
  try {
    foreach ($c in 'halo', 'halod', 'halo-server') { Run 'go' @('build', '-o', (Join-Path $bin "$c.exe"), "./cmd/$c") }
    Run 'go' @('install', 'github.com/distribution/distribution/v3/cmd/registry@v3.0.0')
  } finally { Pop-Location }
  Set-Content -Path (Join-Path $w 'registry.yml') -Value "version: 0.1`nstorage:`n  inmemory: {}`nhttp:`n  addr: $reg"
  Spawn 'registry' (Join-Path $bin 'registry.exe') @('serve', (Join-Path $w 'registry.yml'))

  $pol = Join-Path $w 'pol'; $keys = Join-Path $w 'keys'
  Run 'halo' @('init', $pol, '--org', 'acme', '--full')
  Add-Content -Path (Join-Path $pol 'halos.yaml') -Value "selfService:`n  enabled: true`n  launchers: [laptop]"
  Run 'halo' @('validate', $pol)
  Run 'halo' @('keys', 'generate', '--out', $keys)
  Wait-Until { try { (Invoke-WebRequest -UseBasicParsing "http://$reg/v2/").StatusCode -eq 200 } catch { $false } } 'the local registry'
  Run 'halo' @('release', 'publish', $pol, '--ring', 'ring1-ga', '--release-version', '1.0.0', '--key', (Join-Path $keys 'halo.key'),
    '--registry', "$reg/halos-releases", '--plain-http', '--no-artifacts')

  Copy-Item (Join-Path $bin 'halod.exe') (Join-Path $srv 'halod.exe')
  $sha = (Get-FileHash -Algorithm SHA256 (Join-Path $srv 'halod.exe')).Hash.ToLower()
  @{ baseURL = $base; registry = "$reg/halos-releases"; registryPlainHTTP = $true; pubKeyFile = (Join-Path $keys 'halo.pub')
     halodURL = 'http://127.0.0.1:18200/halod.exe'; halodSHA256 = @{ 'windows-amd64' = $sha } } |
    ConvertTo-Json | Set-Content -Path (Join-Path $w 'portal.json')
  Set-Content -Path (Join-Path $w 'fleet.token') -Value 't'
  Spawn 'files' 'python' @('-m', 'http.server', '18200', '--bind', '127.0.0.1', '--directory', $srv)
  Spawn 'server' (Join-Path $bin 'halo-server.exe') @('--listen', '127.0.0.1:18199', '--policy-dir', $pol,
    '--token-file', (Join-Path $w 'fleet.token'), '--portal-config', (Join-Path $w 'portal.json'),
    '--data-dir', (Join-Path $w 'data'), '--dev-insecure-user', 'dev@acme.com', '--dev-insecure-admin')
  Wait-Until { try { (Invoke-WebRequest -UseBasicParsing "$base/healthz").StatusCode -eq 200 } catch { $false } } 'halo-server'

  Write-Host '== enroll.ps1 (the exact command the portal hands out)'
  $tok = (Invoke-RestMethod -Method Post "$base/api/v1/launch/laptop").token
  & ([scriptblock]::Create((Invoke-RestMethod "$base/enroll.ps1"))) -Token $tok
  if ((Get-FileHash -Algorithm SHA256 $halod).Hash.ToLower() -ne $sha) { Fail 'enroll.ps1 did not install the pinned halod' }
  foreach ($d in 'etc', 'var') { Assert-Acl (Join-Path $halos $d) @($SY, $BA) -Protected }
  Assert-Acl (Join-Path $halos 'etc\halod.yaml') @($SY, $BA)
  if (-not (Select-String -Path (Join-Path $halos 'etc\halod.yaml') -Pattern '^plainHTTP: true' -Quiet)) { Fail 'enrolled config lacks plainHTTP for the local registry' }

  Write-Host '== halod once'
  Run $halod @('once', '--install=false')
  if (-not (Test-Path $settings)) { Fail "no managed settings at $settings" }
  if ((Get-Content -Raw $settings | ConvertFrom-Json).disableBypassPermissionsMode -ne 'disable') { Fail "managed settings content: $(Get-Content -Raw $settings)" }
  Assert-Acl (Split-Path $settings) @($SY, $BA, $BU) -Protected
  Assert-Acl $settings @($SY, $BA, $BU)
  if (((Invoke-RestMethod "$base/api/v1/fleet") | ConvertTo-Json -Depth 8) -notmatch 'dev@acme.com') { Fail 'device missing from the fleet view' }

  Write-Host '== halod service install --start (SYSTEM scheduled task)'
  Remove-Item -Force $settings
  Run $halod @('service', 'install', '--start')
  try { Wait-Until { Test-Path $settings } 'the SYSTEM task to write managed settings' 90 } catch {
    Write-Host '--- task diagnostics'
    schtasks /Query /TN Halos /FO LIST /V
    Get-ScheduledTaskInfo -TaskName Halos | Format-List *
    Get-Process halod -ErrorAction SilentlyContinue | Format-Table Id, SessionId, Path
    Get-ChildItem -Recurse (Join-Path $halos 'var') -ErrorAction SilentlyContinue | Format-Table FullName, Length
    throw
  }
  $q = (schtasks /Query /TN Halos /FO LIST /V) -join "`n"
  if ($q -notmatch 'Run As User:\s+SYSTEM') { Fail "task does not run as SYSTEM:`n$q" }
  if ($q -notmatch 'Status:\s+Running') { Fail "task is not running:`n$q" }
  Assert-Acl $settings @($SY, $BA, $BU)

  Write-Host '== halod service uninstall'
  Run $halod @('service', 'uninstall')
  schtasks /Query /TN Halos *> $null
  if ($LASTEXITCODE -eq 0) { Fail 'scheduled task still registered' }
  Wait-Until { -not (Get-Process -Name halod -ErrorAction SilentlyContinue) } 'halod to stop' 20
  Write-Host 'Windows delivery path OK'
} catch {
  foreach ($f in Get-ChildItem $w -Filter '*.err' -ErrorAction SilentlyContinue) { Write-Host "--- $($f.Name)"; Get-Content $f.FullName -Tail 30 }
  throw
} finally {
  if (Test-Path $halod) { & $halod service uninstall *> $null }
  foreach ($p in $procs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
}
