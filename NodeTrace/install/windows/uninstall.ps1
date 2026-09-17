# Aegis-NodeTrace Uninstallation (Windows)
# Simmetrico a aegis-guard/install/windows/uninstall.ps1: ferma e rimuove il
# servizio e ripulisce la cartella di install. Il .env e i log NON vengono
# toccati (servono alla piattaforma e alla diagnosi).

Write-Host "--- Uninstalling Aegis-NodeTrace ---" -ForegroundColor Cyan

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$installDir = Join-Path $env:ProgramFiles "Aegis\NodeTrace"
$service = "AegisNodeTrace"

$nssmPath = Join-Path $scriptPath "nssm.exe"
if (-not (Test-Path $nssmPath)) {
    $repoRoot = Resolve-Path (Join-Path $scriptPath "..\..\..") -ErrorAction SilentlyContinue
    if ($repoRoot) {
        $sharedNssm = Join-Path $repoRoot.Path "aegis-guard\install\windows\nssm.exe"
        if (Test-Path $sharedNssm) { $nssmPath = $sharedNssm }
    }
}

if (Get-Service $service -ErrorAction SilentlyContinue) {
    Write-Host "Stopping and removing $service service..." -ForegroundColor Yellow
    Stop-Service $service -Force -ErrorAction SilentlyContinue
    if (Test-Path $nssmPath) {
        & $nssmPath remove $service confirm | Out-Null
    } else {
        Write-Warning "nssm.exe non trovato: rimozione del servizio via sc.exe"
        sc.exe delete $service | Out-Null
    }
} else {
    Write-Host "  [i] Servizio $service non presente" -ForegroundColor DarkGray
}

if (Test-Path $installDir) {
    Write-Host "Rimozione $installDir..." -ForegroundColor Yellow
    Remove-Item $installDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "[OK] Aegis-NodeTrace rimosso. I log restano in logs\." -ForegroundColor Green
