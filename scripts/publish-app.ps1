<#
.SYNOPSIS  Builds, tests and publishes the portable RemoteTool.exe (single file, self-contained, no installer).
.PARAMETER SignThumbprint  Optional code-signing certificate thumbprint (cert store). Unsigned remote tools are often flagged by AV.
.PARAMETER SkipTests       Skip unit/integration tests (not recommended).
#>
param(
    [string]$Configuration = "Release",
    [string]$Output = "$PSScriptRoot\..\artifacts\app",
    [string]$SignThumbprint = "",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [switch]$SkipTests
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
Push-Location $root
try {
    & "$PSScriptRoot\check-vulnerabilities.ps1"   # supply chain: fails on known-vulnerable packages, or if the scan cannot run

    if (-not $SkipTests) {
        # Test projects individually: the solution also contains deploy\RemoteTool.Package, which would publish the whole app just to run tests.
        foreach ($t in "Core", "Relay", "Capture") {
            dotnet test "tests/RemoteTool.$t.Tests" -c $Configuration --nologo
            if ($LASTEXITCODE -ne 0) { throw "Tests failed ($t)" }
        }
    }

    if (Test-Path $Output) { Remove-Item -Recurse -Force $Output }
    dotnet publish src/RemoteTool.App -c $Configuration -r win-x64 --self-contained true `
        -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true `
        -o $Output
    if ($LASTEXITCODE -ne 0) { throw "Publish failed" }
    Get-ChildItem $Output -Include *.pdb -Recurse | Remove-Item -Force   # ship the exe only

    $exe = Join-Path $Output "RemoteTool.exe"
    if ($SignThumbprint) {
        $signtool = (Get-Command signtool.exe -ErrorAction Stop).Source
        & $signtool sign /sha1 $SignThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $exe
        if ($LASTEXITCODE -ne 0) { throw "Signing failed" }
        & $signtool verify /pa $exe
    } else {
        Write-Warning "RemoteTool.exe is NOT signed. See docs/BUILD.md (Code signing) before distributing."
    }
    $hash = (Get-FileHash $exe -Algorithm SHA256).Hash
    Set-Content -Path (Join-Path $Output "RemoteTool.exe.sha256") -Value "$hash  RemoteTool.exe"
    Write-Host "Published $exe  SHA-256 $hash"
} finally { Pop-Location }
