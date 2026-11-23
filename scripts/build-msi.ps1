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
    [switch]$ProductionSign,
    [string]$CertificateThumbprint = "",
    [string]$PfxPath = "",
    [string]$PfxPasswordEnv = "AEGIS_MSI_PFX_PASSWORD",
    [switch]$AllowEmptyPfxPassword,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$SignToolPath = ""
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
    "-ext", "WixToolset.Util.wixext",
    "-o", $msi
)
if ($EtwSource) { $args += @("-d", "EtwSource=$EtwSource") }
& $wix @args
if ($LASTEXITCODE -ne 0) { throw "WiX build failed (exit $LASTEXITCODE)" }
if (-not (Test-Path -LiteralPath $msi)) { throw "MSI not produced: $msi" }

function Resolve-SignTool([string]$ExplicitPath) {
    if ($ExplicitPath) {
        if (-not (Test-Path -LiteralPath $ExplicitPath)) {
            throw "signtool.exe not found: $ExplicitPath"
        }
        return (Resolve-Path -LiteralPath $ExplicitPath).Path
    }
    $command = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    if (Test-Path -LiteralPath $kitsRoot) {
        $candidate = Get-ChildItem -LiteralPath $kitsRoot -Recurse -Filter signtool.exe `
            -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($candidate) { return $candidate.FullName }
    }
    throw "signtool.exe not found. Install the Windows SDK or pass -SignToolPath."
}

$productionSigning = $ProductionSign -or (-not $TestSign -and ($CertificateThumbprint -or $PfxPath))
if ($TestSign -and $ProductionSign) {
    throw "Use either -TestSign or -ProductionSign, not both."
}

if ($productionSigning) {
    if (-not $CertificateThumbprint -and -not $PfxPath) {
        throw "Production signing requires -PfxPath or -CertificateThumbprint."
    }
    if ($PfxPath) {
        if (-not (Test-Path -LiteralPath $PfxPath)) {
            throw "PFX not found: $PfxPath"
        }
        $PfxPath = (Resolve-Path -LiteralPath $PfxPath).Path
    }
    if (-not $TimestampUrl -or $TimestampUrl -notmatch '^https?://') {
        throw "A production signature needs an RFC 3161 timestamp URL."
    }
    $signTool = Resolve-SignTool $SignToolPath
    $signArgs = @("sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $TimestampUrl)
    if ($PfxPath) {
        $signArgs += @("/f", $PfxPath)
        $pfxPassword = [Environment]::GetEnvironmentVariable($PfxPasswordEnv)
        if (-not $pfxPassword -and -not $AllowEmptyPfxPassword) {
            throw "Set $PfxPasswordEnv for the PFX, or pass -AllowEmptyPfxPassword for an unencrypted PFX."
        }
        if ($pfxPassword) { $signArgs += @("/p", $pfxPassword) }
    } else {
        $signArgs += @("/sha1", $CertificateThumbprint)
    }
    $signArgs += $msi
    & $signTool @signArgs
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed (exit $LASTEXITCODE)" }
    & $signTool verify /pa /v $msi | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "signtool verify failed (exit $LASTEXITCODE)" }
    $signature = Get-AuthenticodeSignature -FilePath $msi
    if ($signature.Status -ne "Valid") {
        throw "MSI signature is not trusted (status: $($signature.Status)). Install the signing root on this host or use a public certificate."
    }
    if (-not $signature.TimeStamperCertificate) {
        throw "MSI signature has no RFC 3161 timestamp."
    }
    Write-Host "Authenticode production signature: Valid, signer=$($signature.SignerCertificate.Subject), timestamp=$($signature.TimeStamperCertificate.Subject)"
} elseif ($TestSign -or $CertificateThumbprint) {
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
        throw "Authenticode test signing failed: $($_.Exception.Message)"
    }
    $signature = Get-AuthenticodeSignature -FilePath $msi
    if ($signature.Status -eq "NotSigned") {
        throw "MSI is still unsigned after Set-AuthenticodeSignature"
    }
    Write-Host "Authenticode test signature status: $($signature.Status)"
}

$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $msi
"$($hash.Hash.ToLower())  $(Split-Path -Leaf $msi)" |
    Set-Content -LiteralPath "${msi}.sha256" -Encoding ascii

# A test signature is valid only for CI/local smoke. The sidecar makes that
# explicit even if the file is copied out of the workflow artifact.
$mode = if ($productionSigning) { "production" } elseif ($TestSign -or $CertificateThumbprint) { "test" } else { "unsigned" }
$finalSignature = Get-AuthenticodeSignature -FilePath $msi
$signingInfo = [ordered]@{
    schema = "aegis-package-signing-v1"
    package = Split-Path -Leaf $msi
    mode = $mode
    status = [string]$finalSignature.Status
    signer = if ($finalSignature.SignerCertificate) { $finalSignature.SignerCertificate.Subject } else { $null }
    timestamp = if ($finalSignature.TimeStamperCertificate) { $finalSignature.TimeStamperCertificate.Subject } else { $null }
    sha256 = $hash.Hash.ToLower()
}
$signingInfo | ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath "${msi}.signing.json" -Encoding ascii
Write-Host "MSI: $msi"
Write-Host "SHA256: $($hash.Hash.ToLower())"
Write-Host "Signing mode: $mode ($($finalSignature.Status))"
