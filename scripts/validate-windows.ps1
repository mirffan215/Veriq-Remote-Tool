<#
.SYNOPSIS  Smoke-validates the Windows-only parts (service, helper, secure desktop plumbing, H.264) on a TEST Windows 11 PC.
.DESCRIPTION
  Run elevated on a disposable test machine with the SIGNED or unsigned RemoteTool.exe next to this script (or -Exe).
  It installs the service with a throw-away permanent password, checks the pieces that the Linux CI cannot, and uninstalls again.
  Prints PASS/FAIL per check and exits non-zero on any failure. Review docs/SERVICE.md "Validation checklist" for the manual part
  (viewer-side checks: login screen, UAC prompt, Ctrl+Alt+Del) - those need a second PC.
#>
param([string]$Exe = "$PSScriptRoot\RemoteTool.exe", [switch]$KeepInstalled)
$ErrorActionPreference = "Stop"
$script:results = [System.Collections.ArrayList]@()
function Check($name, [scriptblock]$test) {
    $err = $null
    try { $ok = [bool](& $test) } catch { $ok = $false; $err = $_.Exception.Message }
    [void]$script:results.Add([pscustomobject]@{ Check = $name; Result = $(if ($ok) { "PASS" } else { "FAIL" }); Detail = $err })
    Write-Host ("[{0}] {1} {2}" -f $(if ($ok) { "PASS" } else { "FAIL" }), $name, $err)
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")) { throw "Run elevated." }
if ([Environment]::OSVersion.Version.Build -lt 22000) { Write-Warning "Windows 11 (build 22000+) is the supported target; TLS 1.3 will not work on older builds." }

$env:RT_TEST_PW = "Valid4tion-Pass-" + (Get-Random)
Check "exe starts (codec benchmark runs)" { $p = Start-Process $Exe -ArgumentList "--bench-codec", "$env:TEMP\rt-bench.md" -Wait -PassThru; $p.ExitCode -eq 0 -and (Test-Path "$env:TEMP\rt-bench.md") }
Write-Host ("[INFO] H.264 rows in benchmark: {0} (sessions fall back to tiles automatically if none)" -f ((Get-Content "$env:TEMP\rt-bench.md" -Raw) -match "H\.264"))
Check "headless configure succeeds" {
    $p = Start-Process $Exe -ArgumentList "--configure-service", "--relay", "127.0.0.1:8443", "--password-env", "RT_TEST_PW", "--enable", "--name", "VALIDATION" -Wait -PassThru
    $p.ExitCode -eq 0 }
Check "service installed and running" { (Get-Service RemoteToolService).Status -eq "Running" }
Check "service runs the Program Files copy, as LocalSystem" {
    $s = Get-CimInstance Win32_Service -Filter "Name='RemoteToolService'"
    $s.PathName -like "*Program Files*RemoteTool.exe*--service*" -and $s.StartName -eq "LocalSystem" }
Check "program folder not writable by standard users" {
    $acl = Get-Acl "$env:ProgramFiles\RemoteTool"; -not ($acl.Access | Where-Object { $_.IdentityReference -match "Users|Everyone|Authenticated" -and $_.FileSystemRights -match "Write|Modify|FullControl" -and $_.AccessControlType -eq "Allow" }) }
Check "service data folder restricted to SYSTEM/Administrators" {
    $acl = Get-Acl "$env:ProgramData\RemoteTool\service"; -not ($acl.Access | Where-Object { $_.IdentityReference -match "Users|Everyone|Authenticated" }) }
Check "helper process exists in the console session as SYSTEM" {
    Start-Sleep 8
    $h = Get-CimInstance Win32_Process -Filter "Name='RemoteTool.exe'" | Where-Object { $_.CommandLine -like "*--helper*" }
    $h -and ((Invoke-CimMethod -InputObject $h[0] -MethodName GetOwner).User -eq "SYSTEM") }
Check "helper pipe exists (its SYSTEM-only ACL is checked manually, see docs/SERVICE.md)" {
    $pipes = [IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -like "*RemoteTool.Helper.*" }
    $pipes.Count -ge 1 }
Check "public status file readable and contains no secrets" {
    $t = Get-Content "$env:ProgramData\RemoteTool\public\service-status.json" -Raw; ($t -match '"id"') -and ($t -notmatch "Valid4tion|password`"\s*:\s*`"") }
Check "permanent password not stored in clear" { -not (Select-String -Path "$env:ProgramData\RemoteTool\service\*" -Pattern $env:RT_TEST_PW -SimpleMatch -ErrorAction SilentlyContinue) }
Check "audit log hash chain verifies" {
    $p = Start-Process $Exe -ArgumentList "--verify-audit", "$env:ProgramData\RemoteTool\service\logs", "service" -Wait -PassThru; $p.ExitCode -eq 0 }
Check "service survives a crash (recovery action restarts it)" {
    Stop-Process -Name RemoteTool -Force -ErrorAction SilentlyContinue   # kills helper AND service host
    Start-Sleep 12; (Get-Service RemoteToolService).Status -eq "Running" }

if (-not $KeepInstalled) {
    Check "service uninstalls" { Stop-Service RemoteToolService -Force -ErrorAction SilentlyContinue; & sc.exe delete RemoteToolService | Out-Null; -not (Get-Service RemoteToolService -ErrorAction SilentlyContinue) }
}
Remove-Item Env:RT_TEST_PW
$failed = @($script:results | Where-Object Result -eq "FAIL").Count
Write-Host "`n$($script:results.Count - $failed) passed, $failed failed"
exit $(if ($failed) { 1 } else { 0 })
