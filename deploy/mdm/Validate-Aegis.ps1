#Requires -Version 5.1
<#
.SYNOPSIS
    Local validation evidence for an MDM-deployed Aegis agent.
.DESCRIPTION
    Checks the production signature, service, binary version and token ACL.
    It cannot validate an Intune/GPO tenant; that field is reported explicitly.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$MsiPath,
    [string]$ExpectedVersion = '4.3.0'
)
$ErrorActionPreference = 'Stop'
$result = [ordered]@{ schema = 'aegis-mdm-validation-v1'; checked_at = (Get-Date).ToUniversalTime().ToString('o') }
$failures = New-Object System.Collections.Generic.List[string]

if (-not (Test-Path -LiteralPath $MsiPath)) {
    $failures.Add("MSI not found: $MsiPath")
} else {
    $sig = Get-AuthenticodeSignature -FilePath $MsiPath
    $result.authenticode_status = $sig.Status.ToString()
    $result.authenticode_subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
    $result.authenticode_timestamp = if ($sig.TimeStamperCertificate) { $sig.TimeStamperCertificate.Subject } else { $null }
    if ($sig.Status -ne 'Valid') { $failures.Add("Authenticode is $($sig.Status), expected Valid") }
}

$service = Get-Service -Name AegisAgent -ErrorAction SilentlyContinue
$result.service_present = [bool]$service
$result.service_status = if ($service) { $service.Status.ToString() } else { 'missing' }
if (-not $service) { $failures.Add('AegisAgent service missing') }
elseif ($service.Status -ne 'Running') { $failures.Add("AegisAgent is $($service.Status), expected Running") }

$binary = 'C:\Program Files\Aegis\aegis-agent.exe'
if (Test-Path -LiteralPath $binary) {
    $result.product_version = (Get-Item -LiteralPath $binary).VersionInfo.ProductVersion
    if ($result.product_version -notlike "$ExpectedVersion*") {
        $failures.Add("ProductVersion $($result.product_version) does not match $ExpectedVersion")
    }
} else {
    $failures.Add('aegis-agent.exe missing')
}

$token = Join-Path $env:ProgramData 'Aegis\enroll.token'
$result.token_present = Test-Path -LiteralPath $token
if ($result.token_present) {
    $acl = Get-Acl -LiteralPath $token
    $result.token_acl = $acl.Access | ForEach-Object { "$($_.IdentityReference):$($_.FileSystemRights)" }
    if (-not ($acl.Access | Where-Object { $_.IdentityReference -match 'SYSTEM' })) {
        $failures.Add('enroll.token has no SYSTEM ACL')
    }
}

$result.tenant_validation = 'not_performed'
$result.failures = @($failures)
$result.passed = $failures.Count -eq 0
$result | ConvertTo-Json -Depth 5
if ($failures.Count -gt 0) { exit 1 }
exit 0
