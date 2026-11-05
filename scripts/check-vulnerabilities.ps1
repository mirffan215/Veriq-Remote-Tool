<#
.SYNOPSIS  Fails if any project has a known-vulnerable NuGet package (direct or transitive) - or if the scan itself could not run.
.NOTES     Scans each .csproj separately: `dotnet list <solution> package` can fail with a path error on some SDKs, and a scan that
           silently does not run must never be reported as "clean".
#>
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
$bad = @()
foreach ($proj in Get-ChildItem $root -Recurse -Filter *.csproj | Where-Object { $_.FullName -notmatch '[\\/](obj|bin)[\\/]' }) {
    $out = dotnet list $proj.FullName package --vulnerable --include-transitive 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Write-Host $out; throw "Vulnerability scan could not run for $($proj.Name) - treating as failure." }
    if ($out -notmatch "has no vulnerable packages" -and $out -notmatch "no vulnerable packages") {
        if ($out -match "has the following vulnerable packages") { Write-Host $out; $bad += $proj.Name }
        else { Write-Host $out; throw "Unrecognised scan output for $($proj.Name) - treating as failure." }
    }
}
if ($bad.Count) { throw "Vulnerable NuGet packages in: $($bad -join ', ')" }
Write-Host "No known-vulnerable NuGet packages in any project."
