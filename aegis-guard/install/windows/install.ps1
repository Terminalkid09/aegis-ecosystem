# Aegis-Guard Native Installation (Windows)
# Prerequisites: Java 21+, Maven (in PATH), NSSM (nssm.cc)

$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition
$nssmPath = Join-Path $scriptPath "nssm.exe"
$installDir = "C:\Program Files\Aegis\Guard"
$jarPath = Join-Path $installDir "aegis-guard.jar"
$envFile = Join-Path $scriptPath "..\..\.env"
$pomPath = Join-Path $scriptPath "..\..\pom.xml"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "| Aegis-Guard Windows Installation       |" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# === PREREQUISITES CHECK ===
Write-Host "`n[1/6] Checking prerequisites..." -ForegroundColor Cyan

if (-not (Test-Path $nssmPath)) {
    Write-Error ("[X] nssm.exe non trovato in $nssmPath. " +
        "Scaricalo con `python scripts/setup.py` (lo prende e ne verifica l'hash) " +
        "oppure copia nssm.exe (win64) da https://nssm.cc/download in questa cartella.")
    exit 1
}
Write-Host "  [OK] nssm.exe found" -ForegroundColor Green

# Java: il jar è compilato con target 21, quindi serve una JVM 21+.
# Va verificata la **versione**, non la sola presenza: un `java` nel PATH può
# essere la 8 (su questa macchina lo era), il servizio si installa, parte e
# muore con UnsupportedClassVersionError — e in UI l'host semplicemente non
# compare. Inoltre il percorso risolto va usato nel comando di installazione:
# prima c'era la stringa "java", quindi $javaExe veniva calcolato e ignorato.
function Get-JavaMajor([string]$exe) {
    try {
        $first = (& $exe -version 2>&1 | Select-Object -First 1)
        if ("$first" -match 'version "(\d+)(?:\.(\d+))?') {
            $major = [int]$Matches[1]
            if ($major -eq 1 -and $Matches[2]) { return [int]$Matches[2] }   # 1.8 -> 8
            return $major
        }
    } catch { }
    return 0
}

$requiredMajor = 21
$javaCandidates = @()
foreach ($bundled in @("$scriptPath\jre-new\bin\java.exe", "$scriptPath\jre\bin\java.exe")) {
    if (Test-Path $bundled) { $javaCandidates += $bundled }
}
$pathJava = (Get-Command java -ErrorAction SilentlyContinue).Source
if ($pathJava) { $javaCandidates += $pathJava }

$javaExe = $null
foreach ($candidate in $javaCandidates) {
    if ((Get-JavaMajor $candidate) -ge $requiredMajor) { $javaExe = $candidate; break }
}

if (-not $javaExe) {
    Write-Host "  *  Nessuna Java $requiredMajor+ trovata: scarico il JDK portatile..." -ForegroundColor Yellow
    $jreZip = Join-Path $scriptPath "jre.zip"
    Invoke-WebRequest -Uri "https://aka.ms/download-jdk/microsoft-jdk-21-windows-x64.zip" -OutFile $jreZip
    $jreTemp = Join-Path $scriptPath "jre_temp"
    Expand-Archive -Path $jreZip -DestinationPath $jreTemp
    # Va spostata l'intera distribuzione, non solo `bin`: con il solo `bin` il
    # JRE risultante non parte ("could not open ...\lib\jvm.cfg"), ed è
    # esattamente ciò che era rimasto su disco in aegis-guard\jre.
    $inner = (Get-ChildItem $jreTemp -Directory | Select-Object -First 1).FullName
    if (-not $inner) { $inner = $jreTemp }
    $jreDest = Join-Path $scriptPath "jre"
    if (Test-Path $jreDest) { Remove-Item $jreDest -Recurse -Force }
    New-Item -ItemType Directory -Path $jreDest -Force | Out-Null
    Move-Item (Join-Path $inner "*") $jreDest -Force
    Remove-Item $jreZip
    Remove-Item $jreTemp -Recurse
    $javaExe = Join-Path $jreDest "bin\java.exe"
}

$javaMajor = Get-JavaMajor $javaExe
if ($javaMajor -lt $requiredMajor) {
    Write-Error "[X] Serve Java $requiredMajor+ per Aegis-Guard; trovata la versione $javaMajor in $javaExe"
    Write-Host "    Installa una JRE/JDK 21+ (o copia un runtime in '$scriptPath\jre') e ripeti." -ForegroundColor Yellow
    exit 1
}
Write-Host "  [OK] Using Java: $javaExe (major $javaMajor)" -ForegroundColor Green

if ($null -eq (Get-Command mvn -ErrorAction SilentlyContinue)) {
    Write-Error "[X] Maven not found in PATH. Please install Maven 3.8+ and add to PATH."
    exit 1
}
Write-Host "  [OK] Maven found" -ForegroundColor Green

if (-not (Test-Path $pomPath)) {
    Write-Error "[X] pom.xml not found at $pomPath"
    exit 1
}
Write-Host "  [OK] pom.xml found" -ForegroundColor Green

# === ENVIRONMENT LOADING ===
Write-Host "`n[2/6] Loading environment from .env..." -ForegroundColor Cyan

if (-not (Test-Path $envFile)) {
    Write-Error "[X] .env file not found at $envFile"
    exit 1
}

$envVars = @{}
Get-Content $envFile | Where-Object { $_ -match '=' -and -not $_.StartsWith('#') } | ForEach-Object {
    $key, $value = $_.Split('=', 2)
    $key = $key.Trim()
    $value = $value.Trim('"').Trim("'")
    if ($key -and $value) {
        $envVars[$key] = $value
        [Environment]::SetEnvironmentVariable($key, $value, "Process")
    }
}

# Validate required variables
if (-not $envVars['AEGIS_API_KEY']) {
    Write-Error "[X] AEGIS_API_KEY not found in .env"
    exit 1
}
# La chiave di enrollment è **obbligatoria**: `Config.ENROLL_KEY` la legge con
# getEnvOrThrow all'avvio, quindi senza di essa il servizio si installa, parte e
# muore. Prima non veniva passata al servizio (solo AGENT_ENROLL_KEY nel .env,
# con nome diverso da quello che il Java legge).
if (-not ($envVars['AGENT_ENROLL_KEY'] -or $envVars['AEGIS_ENROLL_KEY'])) {
    Write-Error "[X] AGENT_ENROLL_KEY not found in .env — senza chiave di enrollment il servizio non parte."
    exit 1
}
Write-Host "  [OK] AEGIS_API_KEY configured" -ForegroundColor Green
Write-Host "  [OK] enrollment key configured" -ForegroundColor Green
Write-Host "  [OK] Environment loaded" -ForegroundColor Green

# === BUILD / ARTIFACT CHECK ===
Write-Host "`n[3/6] Verifying artifact..." -ForegroundColor Cyan

$jarSource = Join-Path $scriptPath "..\target\aegis-guard.jar"
if (-not (Test-Path $jarSource)) {
    Write-Error "[X] aegis-guard.jar not found at $jarSource`nPlease ensure the project is built or copy the pre-compiled JAR to the 'target' folder."
    exit 1
}
Write-Host "  [OK] Artifact found: aegis-guard.jar" -ForegroundColor Green

# === INSTALLATION DIRECTORY ===
Write-Host "`n[4/6] Creating installation directory..." -ForegroundColor Cyan

New-Item -Path $installDir -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

# Secure directory permissions (Administrators only)
$acl = Get-Acl $installDir
$acl.SetAccessRuleProtection($true, $false)
$adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.SetAccessRule($adminRule)
Set-Acl $installDir $acl

Write-Host "  [OK] Directory created at $installDir" -ForegroundColor Green

# Copy JAR
$jarSource = Join-Path $scriptPath "..\target\aegis-guard.jar"
if (-not (Test-Path $jarSource)) {
    Write-Error "[X] JAR file not found at $jarSource"
    exit 1
}

Copy-Item $jarSource -Destination $jarPath -Force
Write-Host "  [OK] JAR deployed" -ForegroundColor Green

# Telemetria kernel ETW (opzionale ma automatica): se il collector e' stato
# compilato (build.bat step 4 o `make aegis-etw.exe` in aegis-ebpf), viene
# deployato accanto al JAR e la flag accesa. Guard (EtwPipeSource) lo spawna e
# ne legge lo stdout: consumer ETW user-mode, nessun driver, nessuna firma.
# Il servizio gira come LocalSystem, quindi il collector eredita l'elevazione:
# niente UAC, niente passaggi manuali. Se il binario manca, Guard degrada al
# polling Toolhelp32 senza errori: capacita' in meno, non un guasto.
$etwSource = Join-Path $scriptPath "..\..\aegis-ebpf\aegis-etw.exe"
$etwEnabled = "false"
if (Test-Path $etwSource) {
    Copy-Item $etwSource -Destination (Join-Path $installDir "aegis-etw.exe") -Force
    $etwEnabled = "true"
    Write-Host "  [OK] Kernel telemetry (ETW) deployed and enabled" -ForegroundColor Green
} else {
    Write-Host "  [i] aegis-etw.exe non trovato (aegis-ebpf): Guard girera' senza telemetria kernel ETW" -ForegroundColor Yellow
}

# YARA (sandbox statica on-demand sull'endpoint): il binario ufficiale yara64.exe
# va in <install>\bin\ e Guard lo spawn-a per il comando YARA_SCAN. Se manca, le
# scansioni falliscono con ack esplicito (mai "sembra andata").
$yaraSource = Join-Path $scriptPath "bin\yara64.exe"
if (Test-Path $yaraSource) {
    New-Item -ItemType Directory -Force -Path (Join-Path $installDir "bin") | Out-Null
    Copy-Item $yaraSource -Destination (Join-Path $installDir "bin\yara64.exe") -Force
    Write-Host "  [OK] YARA engine deployed (bin/yara64.exe)" -ForegroundColor Green
} else {
    Write-Host "  [i] yara64.exe non trovato in install\windows\bin\: scansioni YARA disabilitate su questo endpoint" -ForegroundColor Yellow
}

# === CONFIGURATION ===
Write-Host "`n[5/6] Configuring service..." -ForegroundColor Cyan

$machineGuid = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name 'MachineGuid').MachineGuid
$agentId = $envVars['AEGIS_AGENT_ID']
if (-not $agentId) {
    $agentId = $machineGuid
}

$gatewayUrl = $envVars['AEGIS_GATEWAY_URL']
if (-not $gatewayUrl) {
    $gatewayUrl = "http://localhost:8088/api/v1/events"
}

# Il brain serve per enrollment, CSR e update. `Config.BRAIN_URL` si aspetta
# l'URL **con** il prefisso /api/v1 (il suo default è
# `https://aegis.local/api/v1`), quindi va composto qui e non lasciato al default:
# senza questa variabile il servizio puntava a aegis.local e l'enrollment falliva.
$brainUrl = $envVars['AEGIS_BRAIN_URL']
if (-not $brainUrl) { $brainUrl = "http://localhost:8000/api/v1" }
if ($brainUrl -match "aegis-brain:8000") {
    $brainUrl = $brainUrl -replace "aegis-brain:8000", "localhost:8000"
}
if ($brainUrl -notmatch "/api/v1/?$") { $brainUrl = $brainUrl.TrimEnd('/') + "/api/v1" }

# Rewrite Docker internal URL to localhost for host execution
if ($gatewayUrl -match "aegis-link:8080") {
    $externalPort = $envVars['LINK_PORT_EXTERNAL']
    if (-not $externalPort) { $externalPort = "8088" }
    $gatewayUrl = $gatewayUrl -replace "aegis-link:8080", "localhost:$externalPort"
}

Write-Host "  Agent ID: $agentId" -ForegroundColor Gray
Write-Host "  Gateway:  $gatewayUrl" -ForegroundColor Gray

# Compute file hash
$hash = Get-FileHash $jarPath -Algorithm SHA256
$hash | Out-File "$installDir\aegis-guard.sha256" -Force
Write-Host "  [OK] File integrity: $($hash.Hash.Substring(0, 16))..." -ForegroundColor Green

# Check if service already exists
if (Get-Service "AegisGuard" -ErrorAction SilentlyContinue) {
    Write-Host "  [i] Service already exists, updating configuration..." -ForegroundColor Yellow
    Stop-Service AegisGuard -Force -ErrorAction SilentlyContinue
    & $nssmPath remove AegisGuard confirm
}

# Install service
& $nssmPath install AegisGuard "$javaExe" "-jar `"$jarPath`""
if ($LASTEXITCODE -ne 0) {
    Write-Error "[X] Failed to install service via NSSM"
    exit 1
}

# Set environment variables for service
$apiKey = $envVars['AEGIS_API_KEY']
if ($envVars['AEGIS_SCAN_INTERVAL_MS']) {
    $scanInterval = $envVars['AEGIS_SCAN_INTERVAL_MS']
} else {
    $scanInterval = '1000'
}

$enrollKey = $envVars['AGENT_ENROLL_KEY']
if (-not $enrollKey) { $enrollKey = $envVars['AEGIS_ENROLL_KEY'] }

# Nota: la chiave di enrollment resta nella configurazione del servizio. È
# inevitabile perché `Config.ENROLL_KEY` è letta all'avvio anche quando
# `secret.json` esiste già; il token di enrollment ha scadenza breve ed è
# monouso, quindi il valore esposto non è una credenziale device.
& $nssmPath set AegisGuard AppEnvironmentExtra `
    "AEGIS_GATEWAY_URL=$gatewayUrl`nAEGIS_BRAIN_URL=$brainUrl`nAEGIS_GUARD_API_KEY=$apiKey`nAEGIS_ENROLL_KEY=$enrollKey`nAEGIS_AGENT_ID=$agentId`nAEGIS_SCAN_INTERVAL_MS=$scanInterval`nAEGIS_ETW_ENABLED=$etwEnabled"

# Set service recovery
& $nssmPath set AegisGuard AppExit Default Restart
& $nssmPath set AegisGuard AppRestartDelay 5000
& $nssmPath set AegisGuard AppStopMethodSkip 0

Write-Host "  [OK] Service configured" -ForegroundColor Green

# === START SERVICE ===
Write-Host "`n[6/6] Starting service..." -ForegroundColor Cyan

Start-Service AegisGuard
Start-Sleep -Seconds 3

$svc = Get-Service AegisGuard -ErrorAction SilentlyContinue
if ($svc.Status -eq "Running") {
    Write-Host "  [OK] Service is RUNNING" -ForegroundColor Green
} else {
    Write-Host "  [X] Service failed to start (Status: $($svc.Status))" -ForegroundColor Red
    Write-Host "`n  Troubleshooting:" -ForegroundColor Yellow
    Write-Host "    - Check Event Viewer: Applications and Services Logs > Windows > NSSM"
    Write-Host "    - Check Java version: & '$javaExe' -version"
    Write-Host "    - Check JAR exists: Test-Path '$jarPath'"
    Write-Host "    - Try manual start: & '$javaExe' -jar '$jarPath'"
    exit 1
}

# === SUCCESS ===
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "| [OK] Installation Successful              |" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan

$installSummary = @"

Service Details:
  Name:        AegisGuard
  Path:        $jarPath
  Agent ID:    $agentId
  Gateway:     $gatewayUrl
  
Management:
  View logs:   Get-EventLog -LogName Application -Source AegisGuard -Newest 20
  Stop:        Stop-Service AegisGuard
  Start:       Start-Service AegisGuard
  Status:      Get-Service AegisGuard
  Uninstall:   .\uninstall.ps1

For issues, check:
  - Windows Event Viewer (Application logs)
  - .env configuration
  - Firewall rules for port 8088
  - Network connectivity to gateway
"@
Write-Host $installSummary -ForegroundColor Green
