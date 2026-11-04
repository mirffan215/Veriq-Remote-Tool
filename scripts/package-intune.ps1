<#
.SYNOPSIS  Stages the Intune Win32 package (.intunewin) from a SIGNED RemoteTool.exe.
.PARAMETER Exe             path to the signed RemoteTool.exe (artifacts\app\RemoteTool.exe)
.PARAMETER IntuneWinAppUtil path to Microsoft's IntuneWinAppUtil.exe (download from github.com/microsoft/Microsoft-Win32-Content-Prep-Tool)
#>
param(
    [string]$Exe = "$PSScriptRoot\..\artifacts\app\RemoteTool.exe",
    [string]$IntuneWinAppUtil,
    [string]$Output = "$PSScriptRoot\..\artifacts\intune"
)
$ErrorActionPreference = "Stop"
if ((Get-AuthenticodeSignature $Exe).Status -ne "Valid") { throw "Sign the exe first (scripts\sign-app.ps1). Unsigned remote tools get blocked." }
$stage = Join-Path $Output "stage"
Remove-Item $Output -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $stage | Out-Null
Copy-Item $Exe $stage
Copy-Item "$PSScriptRoot\..\deploy\intune\*.ps1" $stage
$hash = (Get-FileHash (Join-Path $stage "RemoteTool.exe") -Algorithm SHA256).Hash
(Get-Content (Join-Path $stage "detect.ps1")) -replace "REPLACE_WITH_RELEASE_SHA256", $hash | Set-Content (Join-Path $stage "detect.ps1")
Write-Host "Staged in $stage  (exe SHA-256 $hash baked into detect.ps1)"
if ($IntuneWinAppUtil) {
    & $IntuneWinAppUtil -c $stage -s install.ps1 -o $Output -q
    Write-Host "Package: $(Get-ChildItem $Output -Filter *.intunewin | Select-Object -First 1 -ExpandProperty FullName)"
} else { Write-Warning "IntuneWinAppUtil not given: staged only. Run it on the stage folder with setup file install.ps1." }
