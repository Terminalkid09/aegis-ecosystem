<#
.SYNOPSIS
  Build and test-sign the Aegis Agent MSI.

.DESCRIPTION
  Test signing is intentionally separate from production signing. A self-signed
  certificate is generated in the current-user store for local/CI validation;
  it is never committed and must not be used for a customer release. For a
  production build pass -CertificateThumbprint and install signtool.exe.

  The MSI installs the service but does not start it: an enrollment token must be
  provisioned first (MDM/GPO/Intune or the manual oneliner).
#>
param(
    [string]$Version = "4.3.0",
    [string]$OutDir = "dist",
    [string]$AgentSource = "",
    [string]$EtwSource = "",
    [switch]$TestSign,
    [string]$CertificateThumbprint = ""
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root $OutDir
New-Item -ItemType Directory -Path $out -Force | Out-Null

if (-not $AgentSource) {
    $AgentSource = Join-Path $root ".tmp\packaging\aegis-agent.exe"
    New-Item -ItemType Directory -Path (Split-Path -Parent $AgentSource) -Force | Out-Null
    Push-Location (Join-Path $root "aegis-agent")
    try {
        go build -trimpath -ldflags "-s -w -X main.buildVersion=$Version" `
            -o $AgentSource ./cmd/aegis-agent
    } finally {
        Pop-Location
    }
}
if (-not (Test-Path -LiteralPath $AgentSource)) {
    throw "Agent binary not found: $AgentSource"
}
$AgentSource = (Resolve-Path -LiteralPath $AgentSource).Path

if (-not $EtwSource) {
    $candidate = Join-Path $root "aegis-ebpf\aegis-etw.exe"
    if (Test-Path -LiteralPath $candidate) { $EtwSource = $candidate }
}
if ($EtwSource) { $EtwSource = (Resolve-Path -LiteralPath $EtwSource).Path }

$wix = Join-Path $root ".tmp\wix5\wix.exe"
if (-not (Test-Path -LiteralPath $wix)) {
    $command = Get-Command wix.exe -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "WiX 5 not found. Run: dotnet tool install --tool-path .tmp/wix5 wix --version 5.0.2"
    }
    $wix = $command.Source
}

$wxs = Join-Path $root "aegis-agent\packaging\windows\aegis-agent.wxs"
$msi = Join-Path $out "aegis-agent-$Version-x64.msi"
$args = @(
    "build", $wxs, "-arch", "x64",
    "-d", "Version=$Version",
    "-d", "AgentSource=$AgentSource",
    "-o", $msi
)
if ($EtwSource) { $args += @("-d", "EtwSource=$EtwSource") }
& $wix @args
if ($LASTEXITCODE -ne 0) { throw "WiX build failed (exit $LASTEXITCODE)" }
if (-not (Test-Path -LiteralPath $msi)) { throw "MSI not produced: $msi" }

if ($TestSign -or $CertificateThumbprint) {
    if ($CertificateThumbprint) {
        $cert = Get-Item "Cert:\CurrentUser\My\$CertificateThumbprint"
    } else {
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject "CN=Aegis Test Signing" `
            -FriendlyName "Aegis Test Signing (ephemeral)" `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -KeyUsage DigitalSignature `
            -NotAfter (Get-Date).AddDays(2)
        Export-Certificate -Cert $cert -FilePath (Join-Path $out "aegis-test-signing.cer") | Out-Null
    }
    try {
        Set-AuthenticodeSignature -FilePath $msi -Certificate $cert `
            -HashAlgorithm SHA256 -ErrorAction Stop | Out-Null
    } catch {
        throw "Authenticode signing failed. Install Windows SDK signtool.exe for production signing. $($_.Exception.Message)"
    }
    $signature = Get-AuthenticodeSignature -FilePath $msi
    if ($signature.Status -eq "NotSigned") {
        throw "MSI is still unsigned after Set-AuthenticodeSignature"
    }
    Write-Host "Authenticode test signature status: $($signature.Status)"
}

$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $msi
"$($hash.Hash.ToLower())  $(Split-Path -Leaf $msi)" |
    Set-Content -LiteralPath "$msi.sha256" -Encoding ascii
Write-Host "MSI: $msi"
Write-Host "SHA256: $($hash.Hash.ToLower())"
