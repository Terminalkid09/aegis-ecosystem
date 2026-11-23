#Requires -Version 5.1
# Intune detection rule: exit 0 only for a running, installed AegisAgent.
$ErrorActionPreference = 'Stop'
$service = Get-Service -Name AegisAgent -ErrorAction SilentlyContinue
if (-not $service) { exit 1 }
if ($service.Status -ne 'Running') { exit 1 }
$binary = 'C:\Program Files\Aegis\aegis-agent.exe'
if (-not (Test-Path -LiteralPath $binary)) { exit 1 }
$version = (Get-Item -LiteralPath $binary).VersionInfo.ProductVersion
Write-Output "AegisAgent=$($service.Status); ProductVersion=$version"
exit 0
