@echo off
setlocal EnableDelayedExpansion
title Aegis XDR / SIEM Ecosystem Manager

set "ROOT=%~dp0"
cd /d "%ROOT%"

set "GREEN=[92m"
set "CYAN=[96m"
set "RED=[91m"
set "PURPLE=[95m"
set "YELLOW=[93m"
set "RESET=[0m"

:: `aegis.bat agents batch` : usato dal rilancio elevato, evita il pause finale.
if /i "%~2"=="batch" set "AEGIS_BATCH=1"

if /i "%~1"=="start" goto start_platform
if /i "%~1"=="agents" goto start_agents
if /i "%~1"=="services" goto install_services
if /i "%~1"=="pilot" goto pilot
if /i "%~1"=="stop" goto stop
if /i "%~1"=="clean" goto clean_db
if /i "%~1"=="build" goto build
if /i "%~1"=="install" goto install

:menu
cls
echo  %CYAN%========================================================================%RESET%
echo  %PURPLE%                    AEGIS SIEM / XDR COMMAND CENTER %RESET%
echo  %CYAN%========================================================================%RESET%
echo.
echo  %GREEN%[1]%RESET% Start Backend (Docker) + Frontend (npm start)
echo  %GREEN%[2]%RESET% Start Local Agents (NodeTrace ^& Aegis-Guard)
echo  %GREEN%[P]%RESET% Pilot: platform + agents + verify (one command)
echo  %GREEN%[3]%RESET% Stop All Services (Docker)
echo  %GREEN%[4]%RESET% Clean Database (Wipes DB to apply new schemas)
echo  %GREEN%[5]%RESET% View Agent Logs
echo  %RED%[6] Exit%RESET%
echo.
echo  %CYAN%[B] Build Agents (PyInstaller + Maven + JRE)%RESET%
echo  %CYAN%[S] Installa gli agenti come SERVIZI Windows (admin, autostart, senza prompt)%RESET%
if defined AI_PROFILE (
    echo  %GREEN%  [AI] Locale ON - !AEGIS_MODEL!%RESET%
) else (
    echo  %YELLOW%  [AI] Locale OFF - per attivarla: set AEGIS_WITH_AI=1%RESET%
)
echo.
set /p choice="Select an option: "

if "%choice%"=="1" goto start_platform
if "%choice%"=="2" goto start_agents
if /i "%choice%"=="p" goto pilot
if "%choice%"=="3" goto stop
if "%choice%"=="4" goto clean_db
if "%choice%"=="5" goto view_logs
if "%choice%"=="6" exit /b 0
if /i "%choice%"=="b" goto build
if /i "%choice%"=="s" goto install_services
goto menu

:install
echo.
echo  %CYAN%[*] Installing Frontend dependencies...%RESET%
cd /d "%ROOT%frontend" && call npm install
if errorlevel 1 (
    echo  %RED%[!] npm install failed.%RESET%
    call :maybe_pause
    goto menu_or_exit
)
cd /d "%ROOT%"
echo  %GREEN%[+] Frontend dependencies installed.%RESET%
echo  %CYAN%[*] Run [B]uild to compile agents.%RESET%
call :maybe_pause
goto menu_or_exit

:start_platform
echo.
echo  %PURPLE%[*] Starting Aegis Backend (Docker Compose)...%RESET%
cd /d "%ROOT%"

:: AI locale opzionale. Il container Ollama resta in RAM (~850MB) e in CPU
:: anche a riposo: la detection di Aegis NON ne ha bisogno (le regole sono
:: deterministiche). Avvio leggero di default; per l'AI locale:
::   set AEGIS_WITH_AI=1  &&  aegis.bat start
:: con modello a scelta (anche diversi GB, se il tuo hardware regge):
::   set AEGIS_MODEL=qwen2.5:14b
:: Per puntare a un server Ollama potente in rete invece del container locale,
:: imposta OLLAMA_URL nel .env (es. http://192.168.1.50:11434/api/generate).
set "AI_PROFILE="
if /i "%AEGIS_WITH_AI%"=="1" set "AI_PROFILE=--profile ollama"
if not defined AEGIS_MODEL set "AEGIS_MODEL=llama3"
if defined AI_PROFILE (
    echo  %GREEN%  [+] AI locale: ON - profilo ollama, modello !AEGIS_MODEL!%RESET%
) else (
    echo  %YELLOW%  [i] AI locale: OFF - avvio leggero. Attivabile con: set AEGIS_WITH_AI=1%RESET%
)

call docker compose !AI_PROFILE! up -d
if errorlevel 1 (
    echo  %RED%[!] Docker Compose returned an error. Check for port conflicts or missing images.%RESET%
    echo  %YELLOW%[*] Attempting to continue anyway...%RESET%
)

if defined AI_PROFILE (
    echo  %YELLOW%[*] Pulling !AEGIS_MODEL! model for Ollama - first time only...%RESET%
    start "Ollama Pull" /B cmd /c ""%SystemRoot%\System32\timeout.exe" /t 5 /nobreak >nul && docker exec aegis-ollama ollama pull !AEGIS_MODEL! 2>nul"
)

netstat -ano | findstr ":5173 " | findstr "LISTENING" >nul
if !errorlevel! equ 0 (
    echo  %YELLOW%[!] Port 5173 is already in use. Skipping local vite start.%RESET%
) else (
    if /i "%AEGIS_SKIP_FRONTEND_START%"=="1" (
        echo  %YELLOW%[!] AEGIS_SKIP_FRONTEND_START=1. Frontend launch skipped.%RESET%
    ) else (
        if not exist "%ROOT%frontend\node_modules" (
            echo  %YELLOW%[*] node_modules not found. Running npm install...%RESET%
            cd /d "%ROOT%frontend" && call npm install
            if !errorlevel! neq 0 (
                echo  %RED%[!] npm install failed. Dashboard may not work.%RESET%
            )
            cd /d "%ROOT%"
        )
        echo  %PURPLE%[*] Waiting for backend to initialize...%RESET%
        call :sleep 8
        echo  %CYAN%[*] Starting Vite dev dashboard on http://localhost:5173 ^(container UI: http://localhost:3000^)...%RESET%
        start "Aegis Dashboard" cmd /k "cd /d "%ROOT%frontend" && set VITE_API_URL=http://127.0.0.1:8000/api/v1 && npm run dev"
    )
)
echo  %GREEN%[+] Platform is running!%RESET%
echo  %GREEN%[+] Dev API: http://127.0.0.1:8000/api/v1 ^| Dev UI: http://localhost:5173 ^| Container UI: http://localhost:3000%RESET%
echo  %GREEN%[+] Production (TLS): https://aegis.local (requires hosts file entry)%RESET%
call :maybe_pause
goto menu_or_exit

:view_logs
echo.
echo  %CYAN%[*] Recent agent logs:%RESET%
echo.
if exist "%ROOT%logs\nodetrace.txt" (
    echo  %PURPLE%--- NodeTrace Agent ---%RESET%
    type "%ROOT%logs\nodetrace.txt" 2>nul
) else (
    echo  %YELLOW%No nodetrace log found.%RESET%
)
echo.
if exist "%ROOT%logs\guard.txt" (
    echo  %PURPLE%--- Aegis-Guard Agent ---%RESET%
    type "%ROOT%logs\guard.txt" 2>nul
) else (
    echo  %YELLOW%No guard log found.%RESET%
)
echo.
call :maybe_pause
goto menu_or_exit

:build
call "%ROOT%build.bat"
echo.
call :maybe_pause
goto menu_or_exit

:start_agents
echo.

:: Telemetria kernel ETW: il consumer apre una sessione di trace e richiede
:: privilegi amministrativi, che Windows non concede a un processo avviato
:: senza. Se il collector c'e' e la shell NON e' elevata, il launcher si
:: rilancia elevato (un solo prompt UAC) cosi' l'ETW parte davvero senza
:: configurare nulla; se l'utente rifiuta, gli agenti partono comunque e la
:: copertura mancante e' DICHIARATA (quality=degraded:etw-stream-...).
call :maybe_self_elevate
if !errorlevel! equ 3 exit /b 0

:: Step 0: Auto-build if needed
set "NODETRACE_EXE=%ROOT%NodeTrace\agents\python\dist\nodetrace-agent\nodetrace-agent.exe"
set "GUARD_JAR=%ROOT%aegis-guard\target\aegis-guard.jar"
set "NEED_BUILD="
if not exist "!NODETRACE_EXE!" set "NEED_BUILD=1"
if not exist "!GUARD_JAR!" set "NEED_BUILD=1"
if defined NEED_BUILD (
    echo  %YELLOW%[*] Agent executables not found. Running build first...%RESET%
    call "%ROOT%build.bat"
    if !errorlevel! neq 0 (
        echo  %RED%[!] Build failed. Fix errors and retry.%RESET%
        call :maybe_pause
        goto menu_or_exit
    )
)

call :stop_host_agents

:: Identita' degli agenti: PRESERVATA di default.
:: Prima token.json/secret.json venivano cancellati a OGNI avvio: ogni start
:: registrava un agente NUOVO nel fleet (duplicati, alert attribuiti all'host
:: sbagliato). L'identita' va persa solo quando lo chiedi tu:
::   set AEGIS_RESET_IDENTITY=1  &&  aegis.bat agents
if /i "%AEGIS_RESET_IDENTITY%"=="1" (
    echo  %RED%  [X] AEGIS_RESET_IDENTITY=1: nuova identita' per entrambi gli agenti%RESET%
    if exist "%ROOT%NodeTrace\agents\python\token.json" del /q /f "%ROOT%NodeTrace\agents\python\token.json" 2>nul
    if exist "%ROOT%aegis-guard\secret.json" del /q /f "%ROOT%aegis-guard\secret.json" 2>nul
)
mkdir "%ROOT%logs" 2>nul

echo  %YELLOW%[*] Checking Docker backend is running (http://127.0.0.1:8000)...%RESET%
cmd /c curl -s -o nul http://127.0.0.1:8000/ >nul 2>&1
if !errorlevel! neq 0 (
    echo  %RED%[!] Backend is not reachable at http://127.0.0.1:8000. Start it first with option [1].%RESET%
    call :maybe_pause
    goto menu_or_exit
)
echo  %GREEN%[+] Backend reachable.%RESET%

:: Chiave di enrollment: SOLO dal .env. Qui c'era un default hardcoded, cioe'
:: una credenziale viva scritta nel repository: chiunque leggesse il repo
:: poteva arruolare agenti verso il brain. Meglio fermarsi con un errore chiaro.
for /f "tokens=1,2 delims==" %%A in ('findstr /b "AGENT_ENROLL_KEY=" "%ROOT%.env" 2^>nul') do set "ENV_KEY=%%B"
if not defined ENV_KEY (
    echo  %RED%[X] AGENT_ENROLL_KEY non trovata in .env: gli agenti non possono registrarsi.%RESET%
    echo  %YELLOW%    Impostala nel .env oppure rigenerala dal SOC, poi riprova.%RESET%
    call :maybe_pause
    goto menu_or_exit
)

set "AEGIS_ENROLL_KEY=!ENV_KEY!"

:: Override HTTPS defaults for local dev (agents connect directly to brain, bypassing Caddy).
:: 127.0.0.1 esplicito (audit: "localhost" su Windows tenta prima ::1 con timeout lunghi).
set "NODETRACE_BASE=http://127.0.0.1:8000/api/v1"
set "NODETRACE_REGISTER_URL=%NODETRACE_BASE%/register"
set "NODETRACE_UPDATE_URL=%NODETRACE_BASE%/update"
set "NODETRACE_HEARTBEAT_URL=%NODETRACE_BASE%/heartbeat"
set "AEGIS_BRAIN_URL=%NODETRACE_BASE%"
set "AEGIS_GATEWAY_URL=%NODETRACE_BASE%/telemetry/report"
set "AEGIS_SCAN_INTERVAL_MS=10000"

:: ---- NodeTrace Agent ----
set "PYTHONUNBUFFERED=1"
echo  %YELLOW%[*] Starting NodeTrace Agent...%RESET%
start "NodeTrace Agent" /B "!NODETRACE_EXE!" > "%ROOT%logs\nodetrace.txt" 2>&1
echo  %GREEN%  [+] NodeTrace Agent started (log: logs\nodetrace.txt)%RESET%

:: ---- Guard Agent ----
if not exist "!GUARD_JAR!" (
    echo  %RED%[!] Aegis-Guard JAR not found after build. Run [B]uild manually.%RESET%
    goto :after_guard
)

echo  %YELLOW%[*] Starting Aegis-Guard (Java) EDR Agent...%RESET%

:: Telemetria kernel ETW: compilazione del collector se assente, deploy accanto
:: al JAR ed export delle env che Guard legge. Dettagli in :deploy_etw.
call :deploy_etw

:: YARA: se il binario ufficiale e' in install\windows\bin\, viene copiato
:: nel workdir Guard (bin\) per il comando YARA_SCAN (scansioni on-demand).
if exist "%ROOT%aegis-guard\install\windows\bin\yara64.exe" (
    if not exist "%ROOT%aegis-guard\bin" mkdir "%ROOT%aegis-guard\bin" >nul 2>&1
    copy /y "%ROOT%aegis-guard\install\windows\bin\yara64.exe" "%ROOT%aegis-guard\bin\yara64.exe" >nul
    echo  %GREEN%  [+] YARA engine deployed for Guard%RESET%
) else (
    echo  %YELLOW%  [i] yara64.exe non trovato: scansioni YARA disabilitate%RESET%
)

:: Detect runtime Java: JRE minimale (jlink) > JDK 21+ installato > java di PATH.
:: MAI il primo "java" di PATH alla cieca: e' spesso un JRE 8 e Guard muore con
:: NoClassDefFoundError: jdk/net/Sockets (HttpClient 5 richiede Java 11+).
set "JAVA_CMD="
if exist "%ROOT%aegis-guard\jre-new\bin\java.exe" set "JAVA_CMD=%ROOT%aegis-guard\jre-new\bin\java.exe"
if not defined JAVA_CMD if exist "%ROOT%aegis-guard\jre\bin\java.exe" set "JAVA_CMD=%ROOT%aegis-guard\jre\bin\java.exe"
if not defined JAVA_CMD (
    for /d %%d in ("%ProgramFiles%\Eclipse Adoptium\*" "%ProgramFiles%\Java\jdk*" "%ProgramFiles%\Microsoft\jdk*") do (
        if exist "%%d\bin\java.exe" if exist "%%d\bin\javac.exe" set "JAVA_CMD=%%d\bin\java.exe"
    )
)
if not defined JAVA_CMD set "JAVA_CMD=java"
echo  %YELLOW%  [i] Java runtime per Guard: %JAVA_CMD%%RESET%

pushd "%ROOT%aegis-guard"
start "Aegis-Guard Agent" /B "!JAVA_CMD!" -jar target\aegis-guard.jar > "%ROOT%logs\guard.txt" 2>&1
popd
echo  %GREEN%  [+] Aegis-Guard Agent started (log: logs\guard.txt)%RESET%
echo.

:after_guard
echo  %GREEN%[+] Host agents launched.%RESET%
echo  %GREEN%  Logs: nodetrace.log, aegis-guard.log%RESET%
call :maybe_pause
goto menu_or_exit

:pilot
echo.
echo  %PURPLE%=== AEGIS PILOT: platform + agents + verify (single command) ===%RESET%
where python >nul 2>&1
if errorlevel 1 (
    echo  %RED%[!] Python not found on PATH. Install Python 3.10+ to run pilot.%RESET%
    exit /b 1
)
python "%ROOT%scripts\pilot.py" %~2 %~3 %~4 %~5
exit /b %errorlevel%

:stop
echo.
echo  %RED%[*] Stopping Docker services...%RESET%
cd /d "%ROOT%"
call docker compose down
echo  %RED%[*] NOTE: host agents/background npm windows may need manual close or taskkill.%RESET%
call :maybe_pause
goto menu_or_exit

:clean_db
echo.
echo  %RED%[WARNING] This will wipe the Postgres Database volume!%RESET%
if /i "%AEGIS_BATCH%"=="1" (
    echo  %RED%[!] Refusing clean_db in batch mode.%RESET%
    exit /b 2
)
set /p confirm="Are you sure? (y/n): "
if /i "%confirm%"=="y" (
    call docker compose down -v
    if exist "%ROOT%aegis-guard\secret.json" del /q "%ROOT%aegis-guard\secret.json"
    if exist "%ROOT%NodeTrace\agents\python\secret.json" del /q "%ROOT%NodeTrace\agents\python\secret.json"
    echo  %GREEN%[+] Database wiped. It will be recreated on next startup.%RESET%
)
call :maybe_pause
goto menu_or_exit

:stop_host_agents
:: Chiusura degli agenti host avviati a mano. Windows: nodetrace per nome,
:: Guard con un kill MIRATO (la command line contiene aegis-guard.jar) — prima
:: era `taskkill /f /im java.exe`, che su una workstation chiude OGNI processo
:: Java dell'utente, IDE compresi.
taskkill /f /im nodetrace-agent.exe 2>nul
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*aegis-guard.jar*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" >nul 2>&1
call :sleep 2
exit /b 0

:install_services
echo.
echo  %PURPLE%=== Agenti come servizi Windows (autostart, admin) ===%RESET%
:: La via professionale: la registrazione si fa UNA volta con privilegi e da
:: quel momento gli agenti girano come LocalSystem = admin SEMPRE, senza alcun
:: prompt, e ripartono da soli al boot. Prima bisognava sapere quali due .ps1
:: lanciare, in quale ordine, da un PowerShell elevato: 40 passaggi per una cosa
:: che deve fare il prodotto.
set "ELEVATE_TARGET=services"
call :maybe_self_elevate
if !errorlevel! equ 3 exit /b 0

:: Gli installer copiano gli artefatti: se non ci sono, si compilano prima.
if not exist "%ROOT%aegis-guard\target\aegis-guard.jar" call "%ROOT%build.bat"
if not exist "%ROOT%NodeTrace\agents\python\dist\nodetrace-agent\nodetrace-agent.exe" call "%ROOT%build.bat"

echo  %YELLOW%[*] Registro il servizio Aegis-Guard (LocalSystem)...%RESET%
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%aegis-guard\install\windows\install.ps1"
set "SVC_GUARD=!errorlevel!"
echo  %YELLOW%[*] Registro il servizio NodeTrace...%RESET%
powershell -NoProfile -ExecutionPolicy Bypass -File "%ROOT%NodeTrace\install\windows\install.ps1"
set "SVC_NT=!errorlevel!"

if not "!SVC_GUARD!"=="0" goto services_failed
if not "!SVC_NT!"=="0" goto services_failed

:: Solo ORA si chiudono le istanze avviate a mano: se la registrazione fosse
:: fallita prima, l'endpoint resterebbe senza nessun agente in esecuzione.
:: Ogni endpoint deve avere UN agente: o il servizio o il processo dev.
call :stop_host_agents

echo.
echo  %GREEN%[+] Servizi registrati: partono al boot come LocalSystem.%RESET%
echo  %GREEN%    Da adesso NON usare piu' 'aegis.bat agents': sarebbe una seconda istanza per endpoint.%RESET%
echo  %GREEN%    Telemetria kernel ETW attiva senza prompt (il servizio e' gia' elevato).%RESET%
call :maybe_pause
goto menu_or_exit

:services_failed
:: Un esito va dichiarato: prima si stampava "servizi registrati" anche quando
:: entrambi gli installer erano falliti, e gli agenti a mano venivano chiusi
:: lasciando l'endpoint senza nessuna telemetria.
echo.
:: Attenzione: con EnableDelayedExpansion un `[!]` letterale su una riga che usa
:: !VARIABILI! fa espandere il testo come nome di variabile (l'esito veniva
:: stampato come `[SVC_GUARDSVC_NT).`): qui si usa [X].
echo  %RED%[X] Installazione servizi NON riuscita: Guard=!SVC_GUARD!, NodeTrace=!SVC_NT!.%RESET%
echo  %YELLOW%    Gli agenti avviati a mano restano attivi: l'endpoint non e' scoperto.%RESET%
echo  %YELLOW%    Motivo tipico: serve PowerShell elevato (i servizi richiedono admin).%RESET%
echo  %YELLOW%    Alternativa senza privilegi: powershell -ExecutionPolicy Bypass -File "%ROOT%scripts\install-agents-autostart.ps1"%RESET%
call :maybe_pause
goto menu_or_exit

:maybe_self_elevate
:: Ritorna 3 quando il lavoro e' stato delegato a una istanza elevata.
if not defined ELEVATE_TARGET set "ELEVATE_TARGET=agents"
set "ELEVATE_PRESENT="
if /i "!ELEVATE_TARGET!"=="services" set "ELEVATE_PRESENT=1"
if not defined ELEVATE_PRESENT if exist "%ROOT%aegis-ebpf\aegis-etw.exe" set "ELEVATE_PRESENT=1"
if not defined ELEVATE_PRESENT if exist "%ROOT%aegis-guard\aegis-etw.exe" set "ELEVATE_PRESENT=1"
if not defined ELEVATE_PRESENT exit /b 0
if /i "%AEGIS_NO_ELEVATE%"=="1" exit /b 0
if /i "%AEGIS_ELEVATED%"=="1" exit /b 0
powershell -NoProfile -Command "if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(544)){exit 0}else{exit 1}" >nul 2>&1
if !errorlevel! equ 0 exit /b 0
echo  %YELLOW%[*] Privilegi di amministratore richiesti (%ELEVATE_TARGET%)...%RESET%
:: Windows non consente a un processo avviato dall'utente di elevarsi in
:: silenzio: il consenso UAC e' obbligatorio. Per questo l'elevazione si fa una
:: volta qui, oppure definitivamente con 'aegis.bat services' (servizio).
powershell -NoProfile -Command "$p=Start-Process -FilePath '%ROOT%aegis.bat' -ArgumentList '%ELEVATE_TARGET%','batch' -Verb RunAs -PassThru -Wait; exit $p.ExitCode"
if !errorlevel! neq 0 (
    echo  %RED%  [X] Elevazione non concessa.%RESET%
    if /i "!ELEVATE_TARGET!"=="services" (
        echo  %YELLOW%      I servizi NON sono stati registrati: senza privilegi e' impossibile.%RESET%
    ) else (
        echo  %YELLOW%      Gli agenti partono lo stesso, senza telemetria kernel ETW.%RESET%
        echo  %YELLOW%      Per averla in modo permanente: aegis.bat services, un solo prompt.%RESET%
    )
    exit /b 0
)
echo  %GREEN%  [+] L'istanza elevata ha completato il lavoro.%RESET%
exit /b 3

:deploy_etw
:: Compila (se necessario) e deploya il collector ETW, poi esporta le tre env
:: che Guard legge all'avvio:
::   AEGIS_ETW_ENABLED=true        tenta l'ETW;
::   AEGIS_ETW_PATH=<assoluto>     EtwPipeSource rifiuta i path relativi (non
::                                 esegue binari risolti da un workdir scrivibile);
::   AEGIS_ETW_ALLOW_UNSIGNED=true il collector e' compilato localmente e non ha
::                                 firma Authenticode: senza opt-in viene rifiutato.
:: Sta in una subroutine perche' i messaggi non finiscano dentro un blocco
:: `if ( ... )`, dove le parentesi vanno escapate e rompono il parsing.
set "AEGIS_ETW_ENABLED="
set "AEGIS_ETW_PATH="
set "AEGIS_ETW_ALLOW_UNSIGNED="
if not exist "%ROOT%aegis-ebpf\aegis-etw.exe" call :build_etw
if not exist "%ROOT%aegis-ebpf\aegis-etw.exe" goto deploy_etw_missing
copy /y "%ROOT%aegis-ebpf\aegis-etw.exe" "%ROOT%aegis-guard\aegis-etw.exe" >nul
set "AEGIS_ETW_ENABLED=true"
set "AEGIS_ETW_PATH=%ROOT%aegis-guard\aegis-etw.exe"
set "AEGIS_ETW_ALLOW_UNSIGNED=true"
echo  %GREEN%  [+] Kernel telemetry ETW attiva per Guard%RESET%
exit /b 0

:deploy_etw_missing
echo  %YELLOW%  [i] aegis-etw.exe non disponibile - serve gcc/MinGW per compilarlo.%RESET%
echo  %YELLOW%      Guard parte in polling Toolhelp32 e lo dichiara: quality=degraded%RESET%
exit /b 0

:build_etw
set "GCC_EXE="
for /d %%d in ("%ProgramFiles%\mingw64" "%ProgramFiles%\msys64\mingw64" "C:\mingw64") do (
    if exist "%%d\bin\gcc.exe" set "GCC_EXE=%%d\bin\gcc.exe"
)
if not defined GCC_EXE (
    where gcc >nul 2>&1
    if !errorlevel! equ 0 set "GCC_EXE=gcc"
)
if not defined GCC_EXE exit /b 0
echo  %YELLOW%  [*] Compilazione collector ETW...%RESET%
pushd "%ROOT%aegis-ebpf"
"!GCC_EXE!" -O2 -Wall aegis_etw.c -o aegis-etw.exe -ladvapi32 -ltdh -lws2_32 >nul 2>&1
popd
exit /b 0

:sleep
:: Pausa robusta. Da Git Bash/MSYS il "timeout" di PATH e' quello di coreutils,
:: quindi `timeout /t 2` fallisce con "invalid time interval": si usa l'exe
:: assoluto di Windows, che e' immune allo shadowing.
"%SystemRoot%\System32\timeout.exe" /t %~1 /nobreak >nul 2>&1
exit /b 0

:maybe_pause
if /i "%AEGIS_BATCH%"=="1" exit /b 0
pause
exit /b 0

:menu_or_exit
if not "%~1"=="" exit /b 0
goto menu
