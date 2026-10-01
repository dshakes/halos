# Halos release sha256:4754dce5019b16aeff7c3a499c13935d84aa289dba2a42b2763319e5c236b34b (ring canary). Generated; do not edit.
$ErrorActionPreference = 'Stop'
$key = 'HKLM:\SOFTWARE\Policies\ClaudeCode'
New-Item -Path $key -Force | Out-Null
$json = @'
{"cleanupPeriodDays":30,"env":{"X":"it's"},"model":"opus","permissions":{"deny":["Bash(rm -rf:*)"]},"requiredMaximumVersion":"2.1.0","requiredMinimumVersion":"2.1.0"}
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
$want = @{ 'amd64' = 'abababababababababababababababababababababababababababababababab'; 'arm64' = 'abababababababababababababababababababababababababababababababab' }[$arch]
$url = 'https://d/{os}-{arch}/halod'.Replace('{os}', 'windows').Replace('{arch}', $arch)
$tmp = Join-Path "$dir\bin" 'halod.exe.download'
Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $tmp
$got = (Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash
if ($got -ne $want) { Remove-Item -LiteralPath $tmp -Force; throw "halod sha256 mismatch: $got" }
Move-Item -LiteralPath $tmp -Destination "$dir\bin\halod.exe" -Force
@'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw=
-----END PUBLIC KEY-----
'@ | Set-Content -Encoding ascii "$dir\etc\release.pub"
@'
registry: ghcr.io/a/r
org: acme
ring: canary
pubkey: C:\Program Files\Halos\etc\release.pub
os: windows
'@ | Set-Content -Encoding ascii "$dir\etc\halod.yaml"
$action = New-ScheduledTaskAction -Execute "$dir\bin\halod.exe" -Argument ('run --config "' + $dir + '\etc\halod.yaml" --state "' + $dir + '\var\state.json"')
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'Halos' -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName 'Halos'
