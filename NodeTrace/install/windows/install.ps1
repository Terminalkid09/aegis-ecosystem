# Aegis-NodeTrace Native Installation (Windows) — servizio Windows via NSSM
#
# Perché un servizio e non un processo avviato a mano: i container Docker
# tornano su da soli (restart: unless-stopped), gli agenti host no. Avviati da
# `aegis.bat agents` muoiono con la sessione e dopo un riavvio il SOC vede lo
# stack acceso e zero endpoint. Come servizio NSSM: parte al boot, riparte da
# solo se crasha, e non dipende da nessuna finestra aperta.
#
# Prerequisiti: nssm.exe (nssm.cc) in questa cartella (o in
# aegis-guard/install/windows/), artefatti agenti compilati (`aegis.bat build`),
# PowerShell ELEVATO (l'installazione di un servizio richiede privilegi admin).
#
# Uso:  powershell -ExecutionPolicy Bypass -File NodeTrace\install\windows\install.ps1
param([string]$InstallDir = (Join-Path $env:ProgramFiles "Aegis\NodeTrace"))

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = (Resolve-Path (Join-Path $scriptPath "..\..\..")).Path
$srcExe = Join-Path $repoRoot "NodeTrace\agents\python\dist\nodetrace-agent\nodetrace-agent.exe"
$envFile = Join-Path $repoRoot ".env"
$logDir = Join-Path $repoRoot "logs"
$service = "AegisNodeTrace"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "| Aegis-NodeTrace Windows Installation    |" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# === 1/5 PRIVILEGI ===
Write-Host "`n[1/5] Privilegi..." -ForegroundColor Cyan
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[X] Serve PowerShell elevato: installare un servizio richiede privilegi admin."
    Write-Host "    Senza admin puoi usare gli Scheduled Task (nessun privilegio):" -ForegroundColor Yellow
    Write-Host "    powershell -ExecutionPolicy Bypass -File scripts\install-agents-autostart.ps1" -ForegroundColor Yellow
    exit 1
}
Write-Host "  [OK] PowerShell elevato" -ForegroundColor Green

# === 2/5 PREREQUISITI ===
Write-Host "`n[2/5] Prerequisiti..." -ForegroundColor Cyan
$nssmPath = Join-Path $scriptPath "nssm.exe"
if (-not (Test-Path $nssmPath)) {
    # Riuso quello già scaricato per Guard: un solo nssm per tutta la piattaforma.
    $sharedNssm = Join-Path $repoRoot "aegis-guard\install\windows\nssm.exe"
    if (Test-Path $sharedNssm) { $nssmPath = $sharedNssm }
}
if (-not (Test-Path $nssmPath)) {
    Write-Error ("[X] nssm.exe non trovato. Esegui `python scripts/setup.py` (lo scarica e ne verifica " +
        "l'hash SHA-256) oppure copia nssm.exe da https://nssm.cc/download in `"$scriptPath`".")
    exit 1
}
Write-Host "  [OK] nssm.exe: $nssmPath" -ForegroundColor Green

if (-not (Test-Path $srcExe)) {
    Write-Error "[X] nodetrace-agent.exe assente ($srcExe). Esegui prima: aegis.bat build"
    exit 1
}
Write-Host "  [OK] agente compilato" -ForegroundColor Green

# === 3/5 CONFIGURAZIONE (dal .env) ===
Write-Host "`n[3/5] Lettura configurazione..." -ForegroundColor Cyan
$envVars = @{}
if (Test-Path $envFile) {
    Get-Content $envFile | Where-Object { $_ -match '=' -and -not $_.StartsWith('#') } | ForEach-Object {
        $kv = $_.Split('=', 2)
        if ($kv.Count -eq 2) { $envVars[$kv[0].Trim()] = $kv[1].Trim().Trim('"').Trim("'") }
    }
    Write-Host "  [OK] .env letto" -ForegroundColor Green
} else {
    Write-Host "  [i] .env assente: uso i default di lab" -ForegroundColor Yellow
}

$base = $envVars['AEGIS_BRAIN_URL']
if (-not $base) { $base = "http://127.0.0.1:8000/api/v1" }
$enrollKey = $envVars['AGENT_ENROLL_KEY']
if (-not $enrollKey) { $enrollKey = $envVars['AEGIS_ENROLL_KEY'] }
if (-not $enrollKey) {
    Write-Error "[X] Nessuna AGENT_ENROLL_KEY nel .env: senza chiave l'agente non si registra."
    exit 1
}
# 127.0.0.1 esplicito: su Windows "localhost" tenta prima ::1 e va in timeout.
$serviceUrl = $base -replace 'localhost', '127.0.0.1'

# === 4/5 INSTALLAZIONE DEL SERVIZIO ===
Write-Host "`n[4/5] Installazione servizio..." -ForegroundColor Cyan
if (Get-Service $service -ErrorAction SilentlyContinue) {
    Write-Host "  [i] Servizio esistente: aggiornamento configurazione..." -ForegroundColor Yellow
    Stop-Service $service -Force -ErrorAction SilentlyContinue
    & $nssmPath remove $service confirm | Out-Null
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Copy-Item $srcExe (Join-Path $InstallDir "nodetrace-agent.exe") -Force
$installedExe = Join-Path $InstallDir "nodetrace-agent.exe"

& $nssmPath install $service $installedExe
if ($LASTEXITCODE -ne 0) {
    Write-Error "[X] Installazione del servizio fallita (nssm exit $LASTEXITCODE)"
    exit 1
}
& $nssmPath set $service AppDirectory $InstallDir
# Log del servizio su file: senza questo le righe finiscono solo nell'Event Log
# e il primo debug costa mezz'ora.
& $nssmPath set $service AppStdout (Join-Path $logDir "nodetrace-service.log")
& $nssmPath set $service AppStderr (Join-Path $logDir "nodetrace-service.log")
& $nssmPath set $service AppRotateFiles 1
& $nssmPath set $service AppRotateBytes 10485760
& $nssmPath set $service AppEnvironmentExtra (
    "AEGIS_BRAIN_URL=$serviceUrl`n" +
    "NODETRACE_BASE=$serviceUrl`n" +
    "NODETRACE_REGISTER_URL=$serviceUrl/register`n" +
    "NODETRACE_UPDATE_URL=$serviceUrl/update`n" +
    "NODETRACE_HEARTBEAT_URL=$serviceUrl/heartbeat`n" +
    "AEGIS_ENROLL_KEY=$enrollKey`n" +
    "PYTHONUNBUFFERED=1"
)
# Recovery: come Guard, il servizio riparte da solo se muore.
& $nssmPath set $service AppExit Default Restart
& $nssmPath set $service AppRestartDelay 5000
& $nssmPath set $service AppStopMethodSkip 0
& $nssmPath set $service Start SERVICE_AUTO_START
Write-Host "  [OK] Servizio configurato (AUTO_START, restart on crash)" -ForegroundColor Green

# === 5/5 AVVIO ===
Write-Host "`n[5/5] Avvio servizio..." -ForegroundColor Cyan
Start-Service $service
Start-Sleep -Seconds 4
$svc = Get-Service $service -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "| [OK] AegisNodeTrace RUNNING              |" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "  Install dir: $InstallDir"
    Write-Host "  Log:         $(Join-Path $logDir 'nodetrace-service.log')"
    Write-Host "  Stop:        Stop-Service $service"
    Write-Host "  Start:       Start-Service $service"
    Write-Host "  Status:      Get-Service $service"
    Write-Host "  Disinstalla: powershell -ExecutionPolicy Bypass -File $scriptPath\uninstall.ps1" -ForegroundColor DarkGray
} else {
    Write-Error "[X] Il servizio non e' partito. Controlla: $(Join-Path $logDir 'nodetrace-service.log')"
    exit 1
}
