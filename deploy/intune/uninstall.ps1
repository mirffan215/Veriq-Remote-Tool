# Intune Win32 app - uninstall command:  powershell.exe -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1
$ErrorActionPreference = "Continue"
$exe = Join-Path $env:ProgramFiles "RemoteTool\RemoteTool.exe"
if (Get-Service RemoteToolService -ErrorAction SilentlyContinue) {
    Stop-Service RemoteToolService -Force -ErrorAction SilentlyContinue
    & sc.exe delete RemoteToolService | Out-Null
}
Get-Process RemoteTool -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item (Join-Path $env:ProgramFiles "RemoteTool") -Recurse -Force -ErrorAction SilentlyContinue
# Configuration, audit logs and recordings under %ProgramData%\RemoteTool are KEPT on purpose (evidence). Remove them only per your retention policy.
exit 0
