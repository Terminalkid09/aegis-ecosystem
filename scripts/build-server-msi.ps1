<#
.SYNOPSIS
  Build one of the Aegis Windows server MSIs.

.DESCRIPTION
  The Windows package matrix mirrors the Debian packages:

    aegis-server  - Aegis only (Brain, Link, dashboard, PostgreSQL, Redis, Caddy)
    kraken-server - Kraken only (app, sensors, broker, RDP, private DB/Redis)
    aegis-suite   - both stacks, with the same source as the Linux suite

  Each MSI is self-contained, installs `ak` in the machine PATH, and asks for
  the public FQDN/ACME email/port only when Aegis is included. The packages use
  Docker Desktop at runtime; they do not install a pre-login Windows service.

  Run this script once per edition:
    .\scripts\build-server-msi.ps1 -Edition aegis -Version 4.3.0 -TestSign
    .\scripts\build-server-msi.ps1 -Edition kraken -Version 4.3.0 -TestSign
    .\scripts\build-server-msi.ps1 -Edition suite -Version 4.3.0 -TestSign
#>
param(
    [string]$Version = "4.3.0",
    [string]$OutDir = "dist",
    [ValidateSet("aegis", "kraken", "suite")]
    [string]$Edition = "suite",
    [string]$PayloadDir = "",
    [switch]$TestSign,
    [switch]$ProductionSign,
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

switch ($Edition) {
    "aegis" {
        $productName = "Aegis Server"
        $installFolder = "Aegis Server"
        $featureTitle = "Aegis Server"
        $upgradeCode = "{A1E7F2A0-3E8B-4E8B-9F3D-5A7F1C2D4E61}"
        $registryName = "Server"
        $settingsGuid = "{D1A2B3C4-5D6E-4F70-8123-4567890ABCD1}"
        $akPathGuid = "{D2A2B3C4-5D6E-4F70-8123-4567890ABCD2}"
        $hasAegis = "1"
        $stem = "aegis-server"
    }
    "kraken" {
        $productName = "Kraken Server"
        $installFolder = "Kraken Server"
        $featureTitle = "Kraken Server"
        $upgradeCode = "{B2E7F2A0-3E8B-4E8B-9F3D-5A7F1C2D4E62}"
        $registryName = "Kraken"
        $settingsGuid = "{E1A2B3C4-5D6E-4F70-8123-4567890ABCD3}"
        $akPathGuid = "{E2A2B3C4-5D6E-4F70-8123-4567890ABCD4}"
        $hasAegis = "0"
        $stem = "kraken-server"
    }
    "suite" {
        $productName = "Aegis Suite"
        $installFolder = "Aegis Suite"
        $featureTitle = "Aegis Suite"
        $upgradeCode = "{C7E7F2A0-3E8B-4E8B-9F3D-5A7F1C2D4E60}"
        $registryName = "Suite"
        $settingsGuid = "{F1A2B3C4-5D6E-4F70-8123-4567890ABCD5}"
        $akPathGuid = "{F2A2B3C4-5D6E-4F70-8123-4567890ABCD6}"
        $hasAegis = "1"
        $stem = "aegis-suite"
    }
}

$stage = Join-Path $root ".tmp\server-msi-$Edition-$Version"
if (-not $PayloadDir) {
    $PayloadDir = Join-Path $stage "payload"
    if (Test-Path -LiteralPath $PayloadDir) {
        Remove-Item -LiteralPath $PayloadDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $PayloadDir -Force | Out-Null
} else {
    $PayloadDir = (Resolve-Path -LiteralPath $PayloadDir).Path
}

function Copy-Tree {
    param(
        [string]$Source,
        [string]$Destination,
        [string[]]$ExcludeDirs = @(),
        [string[]]$ExcludeFiles = @()
    )
    if (-not (Test-Path -LiteralPath $Source)) {
        throw "source tree not found: $Source"
    }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $Source -Force) {
        if ($item.PSIsContainer -and $ExcludeDirs -contains $item.Name) { continue }
        if (-not $item.PSIsContainer -and $ExcludeFiles -contains $item.Name) { continue }
        $target = Join-Path $Destination $item.Name
        if ($item.PSIsContainer) {
            Copy-Tree -Source $item.FullName -Destination $target `
                -ExcludeDirs $ExcludeDirs -ExcludeFiles $ExcludeFiles
        } else {
            Copy-Item -LiteralPath $item.FullName -Destination $target -Force
        }
    }
}

function Copy-File {
    param([string]$Source, [string]$Destination)
    if (-not (Test-Path -LiteralPath $Source)) {
        throw "file not found: $Source"
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Destination) -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
}

function Write-Utf8NoBom {
    param([string]$Path, [string]$Text)
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Text, $utf8)
}

function Copy-CommonPayload {
    param([string]$Destination)
    $bin = Join-Path $Destination "bin"
    New-Item -ItemType Directory -Path $bin -Force | Out-Null
    Copy-File (Join-Path $root "packaging\windows\server\ak.cmd") (Join-Path $bin "ak.cmd")
    Copy-File (Join-Path $root "packaging\windows\server\configure-server.ps1") `
        (Join-Path $bin "configure-server.ps1")

    $akText = Get-Content -LiteralPath (Join-Path $root "packaging\windows\server\ak.ps1") -Raw
    $akText = $akText.Replace("__VERSION__", $Version)
    $akText = $akText.Replace("__EDITION__", $Edition)
    $akText = $akText.Replace("__REGISTRY_NAME__", $registryName)
    Write-Utf8NoBom (Join-Path $bin "ak.ps1") $akText

    $docs = Join-Path $Destination "docs"
    Copy-File (Join-Path $root "packaging\server\README.md") (Join-Path $docs "SERVER.md")
    Copy-File (Join-Path $root "docs\AK_CLI.md") (Join-Path $docs "AK_CLI.md")
    Copy-File (Join-Path $root "docs\PACKAGING.md") (Join-Path $docs "PACKAGING.md")
    Copy-File (Join-Path $root "docs\RELEASE_POLICY.md") (Join-Path $docs "RELEASE_POLICY.md")
    Copy-File (Join-Path $root "LICENSE") (Join-Path $docs "LICENSE")
    Copy-File (Join-Path $root "NOTICE") (Join-Path $docs "NOTICE")
    Copy-File (Join-Path $root "THIRD_PARTY_NOTICES.md") (Join-Path $docs "THIRD_PARTY_NOTICES.md")
}

function Build-AegisPayload {
    param([string]$Destination, [switch]$IncludeKraken)
    $aegis = Join-Path $Destination "aegis"
    New-Item -ItemType Directory -Path $aegis -Force | Out-Null

    foreach ($file in @(
        "docker-compose.yml", "docker-compose.prod.yml", "docker-compose.mtls.yml",
        "docker-compose.ha.yml", "Caddyfile", "Caddyfile.mtls", ".env.example"
    )) {
        Copy-File (Join-Path $root $file) (Join-Path $aegis $file)
    }

    Copy-Tree (Join-Path $root "aegis-brain") (Join-Path $aegis "aegis-brain") `
        -ExcludeDirs @(".venv", "__pycache__", ".pytest_cache", ".pytest-temp", "tests",
                       ".ruff_cache", ".mypy_cache", "htmlcov", ".git", ".github") `
        -ExcludeFiles @(".coverage")

    Copy-Tree (Join-Path $root "aegis-link") (Join-Path $aegis "aegis-link") `
        -ExcludeDirs @("target", "test", ".git", ".github") `
        -ExcludeFiles @("link-test.log")

    Copy-Tree (Join-Path $root "frontend") (Join-Path $aegis "frontend") `
        -ExcludeDirs @("node_modules", "dist", "test-results", "e2e", ".vite", ".cache",
                       "coverage", ".git", ".github") `
        -ExcludeFiles @("playwright.config.ts", ".env", ".env.local")

    if ($IncludeKraken) {
        Copy-Tree (Join-Path $root "services\kraken") (Join-Path $aegis "services\kraken") `
            -ExcludeDirs @("tests", "secrets", "data", "monitoring", "nginx", "__pycache__",
                           ".pytest_cache", ".ruff_cache", "htmlcov", ".git", ".github") `
            -ExcludeFiles @(".env", ".coverage")
    }

    New-Item -ItemType Directory -Path (Join-Path $aegis "scripts") -Force | Out-Null
    Copy-File (Join-Path $root "scripts\backup-db.sh") (Join-Path $aegis "scripts\backup-db.sh")
    Copy-File (Join-Path $root "scripts\backup-pki.sh") (Join-Path $aegis "scripts\backup-pki.sh")
    Write-Utf8NoBom (Join-Path $aegis "secrets\README.txt") `
        "This directory is mounted read-only at /run/secrets.`nDo not add secrets here unless the deployment intentionally uses file-mounted secrets.`n"
}

function Build-KrakenPayload {
    param([string]$Destination)
    $kraken = Join-Path $Destination "kraken"
    New-Item -ItemType Directory -Path $kraken -Force | Out-Null
    Copy-File (Join-Path $root "packaging\server\kraken\docker-compose.yml") `
        (Join-Path $kraken "docker-compose.yml")
    Copy-Tree (Join-Path $root "services\kraken") (Join-Path $kraken "services\kraken") `
        -ExcludeDirs @("tests", "secrets", "data", "monitoring", "nginx", "__pycache__",
                       ".pytest_cache", ".ruff_cache", "htmlcov", ".git", ".github") `
        -ExcludeFiles @(".env", ".coverage")
    Write-Utf8NoBom (Join-Path $kraken "secrets\README.txt") `
        "Kraken stores generated secrets in C:\ProgramData\Aegis\secrets.`n"
}

if (-not $PayloadDir) { throw "PayloadDir must not be empty" }

if (-not (Test-Path -LiteralPath (Join-Path $PayloadDir "bin\ak.ps1"))) {
    switch ($Edition) {
        "aegis" {
            Build-AegisPayload -Destination $PayloadDir
        }
        "kraken" {
            Build-KrakenPayload -Destination $PayloadDir
        }
        "suite" {
            Build-AegisPayload -Destination $PayloadDir -IncludeKraken
        }
    }
    Copy-CommonPayload -Destination $PayloadDir
    $bin = Join-Path $PayloadDir "bin"
} else {
    $bin = Join-Path $PayloadDir "bin"
}

# Replace the edition placeholders in a caller-supplied payload too.
$akPath = Join-Path $bin "ak.ps1"
if (Test-Path -LiteralPath $akPath) {
    $text = Get-Content -LiteralPath $akPath -Raw
    $text = $text.Replace("__VERSION__", $Version)
    $text = $text.Replace("__EDITION__", $Edition)
    $text = $text.Replace("__REGISTRY_NAME__", $registryName)
    Write-Utf8NoBom $akPath $text
}

function Get-StableGuid([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) } finally { $sha.Dispose() }
    return ([guid]::new([byte[]]$bytes[0..15])).ToString().ToUpper()
}

function Get-StableId([string]$Value) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)) } finally { $sha.Dispose() }
    return (($bytes[0..7] | ForEach-Object { $_.ToString("x2") }) -join "")
}

$xmlEscape = { param($v) [Security.SecurityElement]::Escape([string]$v) }
$componentIds = New-Object System.Collections.Generic.List[string]
$xml = New-Object System.Text.StringBuilder
[void]$xml.AppendLine('<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">')
[void]$xml.AppendLine('  <Fragment>')
[void]$xml.AppendLine('    <DirectoryRef Id="INSTALLFOLDER">')

function Emit-Directory {
    param(
        [string]$Path,
        [string]$RelativePath,
        [int]$Depth
    )
    $indent = "  " * ($Depth + 3)
    $subIndent = "  " * ($Depth + 4)
    $name = Split-Path -Leaf $Path
    $dirId = "dir_" + (Get-StableId "dir:$RelativePath")
    if ($RelativePath -ne "") {
        [void]$xml.AppendLine("$indent<Directory Id=`"$dirId`" Name=`"$(& $xmlEscape $name)`">")
    }

    $files = @(Get-ChildItem -LiteralPath $Path -File -Force | Sort-Object Name)
    if ($files.Count -gt 0) {
        $componentKey = "component:$RelativePath"
        $componentId = "cmp_" + (Get-StableId $componentKey)
        $componentIds.Add($componentId)
        [void]$xml.AppendLine("$subIndent<Component Id=`"$componentId`" Guid=`"$(Get-StableGuid $componentKey)`">")
        $first = $true
        foreach ($file in $files) {
            $fileKey = "file:$RelativePath/$($file.Name)"
            $fileId = "fil_" + (Get-StableId $fileKey)
            $source = [Security.SecurityElement]::Escape($file.FullName)
            $keyPath = if ($first) { ' KeyPath="yes"' } else { "" }
            [void]$xml.AppendLine("$subIndent  <File Id=`"$fileId`" Source=`"$source`"$keyPath />")
            $first = $false
        }
        [void]$xml.AppendLine("$subIndent</Component>")
    }

    $dirs = @(Get-ChildItem -LiteralPath $Path -Directory -Force | Sort-Object Name)
    foreach ($dir in $dirs) {
        $childRelative = if ($RelativePath) { "$RelativePath/$($dir.Name)" } else { $dir.Name }
        Emit-Directory -Path $dir.FullName -RelativePath $childRelative -Depth ($Depth + 1)
    }

    if ($RelativePath -ne "") {
        [void]$xml.AppendLine("$indent</Directory>")
    }
}

Emit-Directory -Path $PayloadDir -RelativePath "" -Depth 0

[void]$xml.AppendLine('    </DirectoryRef>')
[void]$xml.AppendLine('    <ComponentGroup Id="Payload">')
foreach ($id in $componentIds) {
    [void]$xml.AppendLine("      <ComponentRef Id=`"$id`" />")
}
[void]$xml.AppendLine('    </ComponentGroup>')
[void]$xml.AppendLine('  </Fragment>')
[void]$xml.AppendLine('</Wix>')

New-Item -ItemType Directory -Path $stage -Force | Out-Null
$fragment = Join-Path $stage "payload.wxs"
Write-Utf8NoBom $fragment $xml.ToString()

$wix = Join-Path $root ".tmp\wix5\wix.exe"
if (-not (Test-Path -LiteralPath $wix)) {
    $command = Get-Command wix.exe -ErrorAction SilentlyContinue
    if (-not $command) {
        throw "WiX 5 not found. Run: dotnet tool install --tool-path .tmp/wix5 wix --version 5.0.2"
    }
    $wix = $command.Source
}

$wxs = Join-Path $root "packaging\windows\server\aegis-server.wxs"
$license = Join-Path $root "packaging\windows\server\license.rtf"
$msi = Join-Path $out "$stem-$Version-x64.msi"

$wixArgs = @(
    "build", $wxs, $fragment,
    "-arch", "x64",
    "-ext", "WixToolset.UI.wixext",
    "-d", "Version=$Version",
    "-d", "ProductName=$productName",
    "-d", "InstallFolder=$installFolder",
    "-d", "FeatureTitle=$featureTitle",
    "-d", "UpgradeCode=$upgradeCode",
    "-d", "RegistryName=$registryName",
    "-d", "Edition=$Edition",
    "-d", "HasAegis=$hasAegis",
    "-d", "SettingsGuid=$settingsGuid",
    "-d", "AkPathGuid=$akPathGuid",
    "-d", "LicenseRtf=$license",
    "-o", $msi
)
& $wix @wixArgs
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

if ($TestSign -and $ProductionSign) {
    throw "Use either -TestSign or -ProductionSign, not both."
}

$productionSigning = $ProductionSign -or (-not $TestSign -and $PfxPath)
if ($productionSigning) {
    if (-not $PfxPath) {
        throw "Production signing requires -PfxPath (or -ProductionSign with a PFX)."
    }
    if (-not (Test-Path -LiteralPath $PfxPath)) { throw "PFX not found: $PfxPath" }
    $PfxPath = (Resolve-Path -LiteralPath $PfxPath).Path
    if (-not $TimestampUrl -or $TimestampUrl -notmatch '^https?://') {
        throw "A production signature needs an RFC 3161 timestamp URL."
    }
    $signTool = Resolve-SignTool $SignToolPath
    $signArgs = @("sign", "/fd", "SHA256", "/td", "SHA256", "/tr", $TimestampUrl, "/f", $PfxPath)
    $pfxPassword = [Environment]::GetEnvironmentVariable($PfxPasswordEnv)
    if (-not $pfxPassword -and -not $AllowEmptyPfxPassword) {
        throw "Set $PfxPasswordEnv for the PFX, or pass -AllowEmptyPfxPassword for an unencrypted PFX."
    }
    if ($pfxPassword) { $signArgs += @("/p", $pfxPassword) }
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
    Write-Host "Authenticode production signature: Valid, signer=$($signature.SignerCertificate.Subject)"
} elseif ($TestSign) {
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject "CN=Aegis Test Signing" `
        -FriendlyName "Aegis Server Test Signing (ephemeral)" `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddDays(2)
    Export-Certificate -Cert $cert -FilePath (Join-Path $out "$stem-test-signing.cer") | Out-Null
    Set-AuthenticodeSignature -FilePath $msi -Certificate $cert `
        -HashAlgorithm SHA256 -ErrorAction Stop | Out-Null
    $signature = Get-AuthenticodeSignature -FilePath $msi
    if ($signature.Status -eq "NotSigned") { throw "MSI is still unsigned after Set-AuthenticodeSignature" }
    Write-Host "Authenticode test signature status: $($signature.Status)"
}

$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $msi
"$($hash.Hash.ToLower())  $(Split-Path -Leaf $msi)" |
    Set-Content -LiteralPath "${msi}.sha256" -Encoding ascii
$sig = Get-AuthenticodeSignature -FilePath $msi
$mode = if ($productionSigning) { "production" } elseif ($TestSign) { "test" } else { "unsigned" }
$info = [ordered]@{
    schema = "aegis-package-signing-v1"
    package = Split-Path -Leaf $msi
    edition = $Edition
    mode = $mode
    status = [string]$sig.Status
    signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
    timestamp = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { $null }
    sha256 = $hash.Hash.ToLower()
}
$info | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "${msi}.signing.json" -Encoding ascii
Write-Host "MSI: $msi"
Write-Host "Edition: $Edition"
Write-Host "SHA256: $($hash.Hash.ToLower())"
