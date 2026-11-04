<#
  Intune Win32 app - install command:
      powershell.exe -NoProfile -ExecutionPolicy Bypass -File install.ps1
  Runs as SYSTEM. Copies the SIGNED RemoteTool.exe to Program Files and (optionally) configures the unattended-access service.
  SECRETS: edit the three variables below ONLY in your private copy of this script (Intune keeps script contents visible to Intune admins),
  or better: fetch them at run time from Azure Key Vault / your secret store and set the environment variables before calling the exe.
#>
$ErrorActionPreference = "Stop"
$Relay        = "relay1.example.com:443,relay2.example.com:443"   # failover list
$RelayFp      = ""                                               # optional SHA-256 pin(s), comma separated
$InstallDir   = Join-Path $env:ProgramFiles "RemoteTool"
$UnattendedPC = $false                                           # $true => install the SYSTEM service with a permanent password (servers, kiosks)

$src = Join-Path $PSScriptRoot "RemoteTool.exe"
$sig = Get-AuthenticodeSignature $src
if ($sig.Status -ne "Valid") { throw "RemoteTool.exe is not validly signed ($($sig.Status)) - refusing to install." }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item $src (Join-Path $InstallDir "RemoteTool.exe") -Force

if ($UnattendedPC) {
    # Values come from the environment so they never appear in a process command line.
    if (-not $env:RT_RELAY_KEY -or -not $env:RT_PERMANENT_PASSWORD) { throw "Set RT_RELAY_KEY and RT_PERMANENT_PASSWORD (from your secret store) before running." }
    & (Join-Path $InstallDir "RemoteTool.exe") --configure-service --relay $Relay --relay-fp $RelayFp `
        --relay-key-env RT_RELAY_KEY --password-env RT_PERMANENT_PASSWORD --enable
    # --configure-service is asynchronous w.r.t. its GUI subsystem: wait for it, then read its log
    Start-Sleep -Seconds 20
    $log = Join-Path $env:ProgramData "RemoteTool\configure-service.log"
    if (Test-Path $log) { Get-Content $log -Tail 5 }
    if ((Get-Service RemoteToolService -ErrorAction SilentlyContinue).Status -ne "Running") { throw "Service did not start; see $log" }
}
# Regular users: first launch uses REMOTETOOL_RELAY / _KEY / _FP if you set them machine-wide (see docs/INTUNE.md).
[Environment]::SetEnvironmentVariable("REMOTETOOL_RELAY", $Relay, "Machine")
if ($RelayFp) { [Environment]::SetEnvironmentVariable("REMOTETOOL_RELAY_FP", $RelayFp, "Machine") }
exit 0
