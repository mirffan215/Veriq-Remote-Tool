<#
.SYNOPSIS  Builds the single-file package of one or all editions (Enterprise, Production, UAT) from the shared source.
.PARAMETER Edition  Enterprise | Production | UAT | All (default)
.PARAMETER SkipTests  Skip the unit tests that run first.
Relay defaults per edition come from environment variables (never from the repository):
    RT_ENTERPRISE_RELAY / _RELAY_FP / _RELAY_KEY      RT_PROD_RELAY / _RELAY_FP / _RELAY_KEY      RT_UAT_RELAY / _RELAY_FP / _RELAY_KEY
Output: artifacts\<Edition>\<exe> (+ .sha256, README.txt) and artifacts\<Edition>-<version>-win-x64.zip
#>
param(
    [ValidateSet("All", "Enterprise", "Production", "UAT")][string]$Edition = "All",
    [switch]$SkipTests
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
Push-Location $root
try {
    if (-not $SkipTests) {
        foreach ($t in "Core", "Relay", "Capture") {
            dotnet test "tests/RemoteTool.$t.Tests" -c Release --nologo
            if ($LASTEXITCODE -ne 0) { throw "Tests failed ($t)" }
        }
    }
    $list = if ($Edition -eq "All") { "Enterprise", "Production", "UAT" } else { @($Edition) }
    foreach ($e in $list) {          # one after the other: editions share the app's obj folder
        Write-Host "=== $e ===" -ForegroundColor Cyan
        dotnet build "editions\$e" -c Release --nologo
        if ($LASTEXITCODE -ne 0) { throw "Edition build failed ($e)" }
    }
    Write-Host ""
    Get-ChildItem "$root\artifacts" -Recurse -Include *.exe, *.zip | ForEach-Object { "{0,-70} {1,8:N1} MB" -f $_.FullName.Substring($root.Path.Length + 1), ($_.Length / 1MB) }
} finally { Pop-Location }
