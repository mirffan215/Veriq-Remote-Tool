<#
.SYNOPSIS  Authenticode-signs (SHA-256, RFC 3161 timestamp) and verifies a RemoteTool binary.
.DESCRIPTION
  Pick ONE certificate source:
    -Thumbprint <sha1>         certificate in the Windows cert store (smart card / HSM / EV token appear here too)
    -PfxPath <file>            PFX file; the password is read from the environment variable named by -PfxPasswordEnv (never from the command line)
    -AzureSigningMetadata <f>  Azure Trusted Signing metadata JSON (needs the Azure.CodeSigning dlib via -AzureDlib)
  Never commit certificates or passwords. Keep the private key in an HSM / Key Vault where you can.
#>
param(
    [Parameter(Mandatory)] [string]$File,
    [string]$Thumbprint,
    [string]$PfxPath,
    [string]$PfxPasswordEnv = "RT_SIGN_PFX_PASSWORD",
    [string]$AzureSigningMetadata,
    [string]$AzureDlib,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)
$ErrorActionPreference = "Stop"
$signtool = (Get-Command signtool.exe -ErrorAction Stop).Source
if ($Thumbprint) {
    & $signtool sign /sha1 $Thumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 /d "RemoteTool" $File
} elseif ($PfxPath) {
    $pw = [Environment]::GetEnvironmentVariable($PfxPasswordEnv)
    if (-not $pw) { throw "Set the PFX password in environment variable $PfxPasswordEnv" }
    & $signtool sign /f $PfxPath /p $pw /fd SHA256 /tr $TimestampUrl /td SHA256 /d "RemoteTool" $File
} elseif ($AzureSigningMetadata -and $AzureDlib) {
    & $signtool sign /v /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 /dlib $AzureDlib /dmdf $AzureSigningMetadata $File
} else { throw "Choose a certificate source (-Thumbprint, -PfxPath or -AzureSigningMetadata/-AzureDlib)." }
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed" }
& $signtool verify /pa /v $File
if ($LASTEXITCODE -ne 0) { throw "signature verification failed" }
$sig = Get-AuthenticodeSignature $File
Write-Host "Signed by: $($sig.SignerCertificate.Subject)  status: $($sig.Status)"
Write-Host "SHA-256: $((Get-FileHash $File -Algorithm SHA256).Hash)"
