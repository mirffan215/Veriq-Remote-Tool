<#
.SYNOPSIS  Builds, tests and publishes the self-contained relay. Use -Runtime linux-x64 for a Linux VPS.
#>
param(
    [string]$Configuration = "Release",
    [ValidateSet("win-x64", "linux-x64")] [string]$Runtime = "win-x64",
    [string]$Output = "$PSScriptRoot\..\artifacts\relay-$Runtime",
    [switch]$SkipTests
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
Push-Location $root
try {
    & "$PSScriptRoot\check-vulnerabilities.ps1"   # supply chain: fails on known-vulnerable packages, or if the scan cannot run
    if (-not $SkipTests) {
        dotnet test tests/RemoteTool.Relay.Tests -c $Configuration --nologo
        if ($LASTEXITCODE -ne 0) { throw "Tests failed" }
    }
    if (Test-Path $Output) { Remove-Item -Recurse -Force $Output }
    dotnet publish src/RemoteTool.Relay -c $Configuration -r $Runtime --self-contained true `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -o $Output
    if ($LASTEXITCODE -ne 0) { throw "Publish failed" }
    Write-Host "Published relay to $Output"
} finally { Pop-Location }
