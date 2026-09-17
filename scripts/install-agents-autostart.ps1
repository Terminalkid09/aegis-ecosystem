# Aegis — Autostart degli agenti host su Windows: FALLBACK senza privilegi.
#
# La via primaria e' un'altra, ed e' quella che usa l'installazione: gli
# agenti vengono registrati come SERVIZI Windows (NSSM), che partono al boot,
# ripartono da soli se crashano e girano elevati (necessario a Guard per le
# azioni di risposta). La registra `scripts/setup.py` quando ha privilegi, o
# a mano:
#   powershell -ExecutionPolicy Bypass -File aegis-guard\install\windows\install.ps1
#   powershell -ExecutionPolicy Bypass -File NodeTrace\install\windows\install.ps1
#
# Questo script serve a chi NON puo'/vuole installare servizi: usa schtasks
# (task "al logon", contesto utente, nessun nssm). Limite dichiarato: Guard
# non elevato non puo' terminare processi di altri utenti.
#
# Perché esiste: i container Docker tornano su da soli (restart: unless-stopped)
# ma gli agenti host no: avviati a mano muoiono con la sessione e dopo un
# riavvio il SOC vede lo stack acceso e zero endpoint.
#
# Uso:  powershell -ExecutionPolicy Bypass -File scripts/install-agents-autostart.ps1
#       ... -Remove   per disinstallare
#
# Nota privilegi: senza elevazione Guard raccoglie telemetria e risponde a
# comandi che non richiedono diritti su altri processi. Per le azioni di
# risposta complete l'agente va eseguito elevato: in quel caso il percorso
# giusto e' l'installer (install.ps1), che lo registra come servizio NSSM.
param([switch]$Remove)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$logs = Join-Path $root "logs"
$guardDir = Join-Path $root "aegis-guard"
$ntExe = Join-Path $root "NodeTrace\agents\python\dist\nodetrace-agent\nodetrace-agent.exe"
$guardJar = Join-Path $guardDir "target\aegis-guard.jar"
$envLauncher = Join-Path $logs "autostart-env.cmd"
$ntRunner = Join-Path $logs "run-nodetrace.cmd"
$guardRunner = Join-Path $logs "run-guard.cmd"

function Remove-AegisTasks {
    foreach ($t in @("AegisNodeTrace", "AegisGuardAgent")) {
        $existing = schtasks /query /tn $t 2>$null
        if ($LASTEXITCODE -eq 0) {
            schtasks /delete /tn $t /f | Out-Null
            Write-Host "  [-] Task rimosso: $t" -ForegroundColor Yellow
        } else {
            Write-Host "  [i] Task assente: $t" -ForegroundColor DarkGray
        }
    }
    foreach ($f in @($envLauncher, $ntRunner, $guardRunner)) {
        if (Test-Path $f) { Remove-Item $f -Force }
    }
}

function Register-Task($name, $command) {
    # /sc onlogon: parte al logon dell'utente, nello stesso contesto dei permessi.
    schtasks /create /tn $name /tr $command /sc onlogon /f | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [+] Task $name registrato" -ForegroundColor Green
    } else {
        Write-Host "  [!] Registrazione $name fallita (prova da PowerShell elevato)" -ForegroundColor Yellow
    }
}

if ($Remove) {
    Write-Host "[*] Rimozione autostart agenti Aegis..." -ForegroundColor Cyan
    Remove-AegisTasks
    exit 0
}

Write-Host "[*] Configurazione autostart agenti Aegis..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $logs | Out-Null

# --- chiavi/URL dal .env (stessa precedenza di aegis.bat) --------------------
$enrollKey = "aegis-enroll-e17f250567d35991aadc5e60"
$envFile = Join-Path $root ".env"
if (Test-Path $envFile) {
    $line = Get-Content $envFile | Where-Object { $_ -match '^AGENT_ENROLL_KEY=' } | Select-Object -First 1
    if ($line) { $enrollKey = ($line -split '=', 2)[1].Trim() }
}
$base = "http://127.0.0.1:8000/api/v1"

Set-Content -Path $envLauncher -Encoding ASCII -Value @(
    "@echo off",
    "set `"AEGIS_BRAIN_URL=$base`"",
    "set `"AEGIS_GATEWAY_URL=$base/telemetry/report`"",
    "set `"AEGIS_ENROLL_KEY=$enrollKey`"",
    "set `"AEGIS_SCAN_INTERVAL_MS=10000`"",
    "set `"NODETRACE_BASE=$base`"",
    "set `"NODETRACE_REGISTER_URL=$base/register`"",
    "set `"NODETRACE_UPDATE_URL=$base/update`"",
    "set `"NODETRACE_HEARTBEAT_URL=$base/heartbeat`"",
    "set `"PYTHONUNBUFFERED=1`""
)

# --- NodeTrace ---------------------------------------------------------------
if (Test-Path $ntExe) {
    Set-Content -Path $ntRunner -Encoding ASCII -Value @(
        "@echo off",
        "call `"$envLauncher`"",
        "cd /d `"$(Split-Path -Parent $ntExe)`"",
        "`"$ntExe`" >> `"$logs\nodetrace.txt`" 2>&1"
    )
    Register-Task "AegisNodeTrace" "`"$ntRunner`""
    Write-Host "      log: logs\nodetrace.txt" -ForegroundColor DarkGray
} else {
    Write-Host "  [!] nodetrace-agent.exe assente: esegui prima 'aegis.bat build'" -ForegroundColor Yellow
}

# --- Guard: solo se non c'e' il servizio NSSM (che ha privilegi pieni) -------
if (Get-Service "AegisGuard" -ErrorAction SilentlyContinue) {
    Write-Host "  [i] Servizio AegisGuard presente: autostart gia' gestito dal servizio" -ForegroundColor DarkGray
} elseif (-not (Test-Path $guardJar)) {
    Write-Host "  [!] aegis-guard.jar assente: esegui prima 'aegis.bat build'" -ForegroundColor Yellow
} else {
    $java = $null
    foreach ($cand in @((Join-Path $guardDir "jre-new\bin\java.exe"), (Join-Path $guardDir "jre\bin\java.exe"))) {
        if (Test-Path $cand) { $java = $cand; break }
    }
    if (-not $java) {
        $java = Get-ChildItem "$env:ProgramFiles\Eclipse Adoptium\*\bin\java.exe",
                                "$env:ProgramFiles\Java\jdk*\bin\java.exe",
                                "$env:ProgramFiles\Microsoft\jdk*\bin\java.exe" `
                 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $java) {
        Write-Host "  [!] Nessun Java 21+ trovato: Guard non registrato (NodeTrace si')" -ForegroundColor Yellow
    } else {
        Set-Content -Path $guardRunner -Encoding ASCII -Value @(
            "@echo off",
            "call `"$envLauncher`"",
            "cd /d `"$guardDir`"",
            "`"$java`" -jar `"$guardJar`" >> `"$logs\guard.txt`" 2>&1"
        )
        Register-Task "AegisGuardAgent" "`"$guardRunner`""
        Write-Host "      log: logs\guard.txt (avvio non elevato: per le azioni di" -ForegroundColor DarkGray
        Write-Host "      risposta complete usa l'installer come servizio NSSM)" -ForegroundColor DarkGray
    }
}

Write-Host "[OK] Al prossimo logon gli agenti ripartono da soli. Rimozione: -Remove" -ForegroundColor Green
