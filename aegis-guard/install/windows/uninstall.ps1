# Aegis-Guard Uninstallation (Windows)

Write-Host "--- Uninstalling Aegis-Guard ---" -ForegroundColor Cyan

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$nssmPath = Join-Path $scriptPath "nssm.exe"
$installDir = "C:\Program Files\Aegis\Guard"

if (Get-Service "AegisGuard" -ErrorAction SilentlyContinue) {
    Write-Host "Stopping and removing AegisGuard service..."
    Stop-Service "AegisGuard"
    if (Test-Path $nssmPath) {
        & $nssmPath remove AegisGuard confirm
    } else {
        Write-Warning "nssm.exe not found. Attempting to delete service via sc.exe..."
        sc.exe delete AegisGuard
    }
}

if (Test-Path $installDir) {
    Write-Host "Removing installation files..."
    Remove-Item -Path $installDir -Recurse -Force
}

Write-Host "Aegis-Guard has been successfully uninstalled." -ForegroundColor Green
