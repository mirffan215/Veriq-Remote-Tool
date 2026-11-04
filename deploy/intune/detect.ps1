# Intune Win32 app - detection script. Prints something and exits 0 only when the expected, correctly signed build is present.
$exe = Join-Path $env:ProgramFiles "RemoteTool\RemoteTool.exe"
$expected = "REPLACE_WITH_RELEASE_SHA256"      # from artifacts\app\RemoteTool.exe.sha256 of the signed release
if (-not (Test-Path $exe)) { exit 1 }
if ((Get-AuthenticodeSignature $exe).Status -ne "Valid") { exit 1 }
if ((Get-FileHash $exe -Algorithm SHA256).Hash -ne $expected) { exit 1 }
Write-Output "RemoteTool installed"
exit 0
