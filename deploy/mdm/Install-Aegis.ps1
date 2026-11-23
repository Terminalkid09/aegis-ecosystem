#Requires -Version 5.1
<#
.SYNOPSIS
    Install the signed Aegis MSI and provision a one-shot enrollment token.
.DESCRIPTION
    Intune Win32 wrapper. Refuses a non-production signature. If no token file
    is supplied the service is left stopped: a missing token must be visible,
    not a successful-looking agent with no enrollment.
#>
[CmdletBinding()]
param(
    [string]$MsiPath = (Join-Path $PSScriptRoot 'aegis-agent.msi'),
    [string]$BrainUrl = 'https://aegis.local',
    [string]$EnrollTokenFile,
    [switch]$KeepServiceStopped
)

$ErrorActionPreference = 'Stop'
$log = [ordered]@{ step = 'install'; ok = $false; msi = $MsiPath }

if (-not (Test-Path -LiteralPath $MsiPath)) { throw "MSI not found: $MsiPath" }
$signature = Get-AuthenticodeSignature -FilePath $MsiPath
if ($signature.Status -ne 'Valid') {
    throw "MSI Authenticode status is $($signature.Status), expected Valid"
}
if (-not $signature.TimeStamperCertificate) {
    throw 'MSI has no RFC 3161 timestamp certificate'
}
if ($BrainUrl -notmatch '^https://') { throw "BRAIN_URL must use HTTPS" }

$arguments = @('/i', "`"$MsiPath`"", '/qn', '/norestart', "BRAIN_URL=$BrainUrl")
$install = Start-Process -FilePath msiexec.exe -ArgumentList $arguments -Wait -PassThru
if ($install.ExitCode -notin @(0, 1641, 3010)) {
    throw "msiexec failed with exit code $($install.ExitCode)"
}

$service = Get-Service -Name AegisAgent -ErrorAction SilentlyContinue
if (-not $service) { throw 'AegisAgent service was not registered' }

if ($EnrollTokenFile) {
    if (-not (Test-Path -LiteralPath $EnrollTokenFile)) {
        throw "Enrollment token file not found: $EnrollTokenFile"
    }
    $tokenDir = Join-Path $env:ProgramData 'Aegis'
    New-Item -ItemType Directory -Force -Path $tokenDir | Out-Null
    $tokenPath = Join-Path $tokenDir 'enroll.token'
    Copy-Item -LiteralPath $EnrollTokenFile -Destination $tokenPath -Force
    & icacls.exe $tokenPath /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Failed to set ACL on $tokenPath" }
}

if ($KeepServiceStopped) {
    Stop-Service -Name AegisAgent -Force -ErrorAction SilentlyContinue
    $log.warning = 'Service left stopped (KeepServiceStopped)'
} elseif (-not $EnrollTokenFile) {
    Stop-Service -Name AegisAgent -Force -ErrorAction SilentlyContinue
    $log.warning = 'No token provided; service left stopped'
} else {
    Start-Service -Name AegisAgent
    $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
}
$log.ok = $true
$log.service = (Get-Service -Name AegisAgent).Status.ToString()
$log | ConvertTo-Json
exit 0
