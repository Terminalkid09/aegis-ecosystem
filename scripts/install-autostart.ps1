# Aegis - Docker Desktop autostart for a Windows PC.
#
# Containers with `restart: unless-stopped` return only after the Docker engine
# is running. Docker Desktop is a per-user application: this adds it to the
# current user's Run key. It is not a pre-login server service.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\install-autostart.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\install-autostart.ps1 -Remove
param([switch]$Remove)

$ErrorActionPreference = "Stop"
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$name = "Docker Desktop"
$docker = Join-Path $env:ProgramFiles "Docker\Docker\Docker Desktop.exe"

if ($Remove) {
    if (Test-Path $runKey) {
        Remove-ItemProperty -Path $runKey -Name $name -ErrorAction SilentlyContinue
    }
    Write-Host "[OK] Docker Desktop autostart removed for the current user."
    exit 0
}

if (-not (Test-Path -LiteralPath $docker)) {
    throw "Docker Desktop not found at $docker. Install Docker Desktop first."
}

New-Item -Path $runKey -Force | Out-Null
Set-ItemProperty -Path $runKey -Name $name -Value "`"$docker`""
Write-Host "[OK] Docker Desktop will start at the next user sign-in."
Write-Host "     Long-running Aegis/Kraken containers use restart: unless-stopped."
Write-Host "     For unattended, pre-login availability use Linux Docker Engine."
