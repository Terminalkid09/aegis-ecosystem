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

if /i "%~1"=="start" goto start_platform
if /i "%~1"=="agents" goto start_agents
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
echo  %GREEN%[3]%RESET% Stop All Services (Docker)
echo  %GREEN%[4]%RESET% Clean Database (Wipes DB to apply new schemas)
echo  %GREEN%[5]%RESET% View Agent Logs
echo  %RED%[6] Exit%RESET%
echo.
echo  %CYAN%[B] Build Agents (PyInstaller + Maven + JRE)%RESET%
echo.
set /p choice="Select an option: "

if "%choice%"=="1" goto start_platform
if "%choice%"=="2" goto start_agents
if "%choice%"=="3" goto stop
if "%choice%"=="4" goto clean_db
if "%choice%"=="5" goto view_logs
if "%choice%"=="6" exit /b 0
if /i "%choice%"=="b" goto build
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
call docker compose --profile ollama up -d
if errorlevel 1 (
    echo  %RED%[!] Docker Compose returned an error. Check for port conflicts or missing images.%RESET%
    echo  %YELLOW%[*] Attempting to continue anyway...%RESET%
)

echo  %YELLOW%[*] Pulling Llama3 model for Ollama (first time only)...%RESET%
start "Ollama Pull" /B cmd /c "timeout /t 5 >nul && docker exec aegis-ollama ollama pull llama3 2>nul"

netstat -ano | findstr ":3000 " | findstr "LISTENING" >nul
if !errorlevel! equ 0 (
    echo  %YELLOW%[!] Port 3000 is already in use. Skipping local npm start.%RESET%
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
        timeout /t 8 >nul
        echo  %CYAN%[*] Starting React Dashboard (dev) on http://localhost:3000...%RESET%
        echo  %CYAN%[*] Production dashboard: https://aegis.local (via Caddy TLS)%RESET%
        start "Aegis Dashboard" cmd /k "cd /d "%ROOT%frontend" && set REACT_APP_API_URL=http://localhost:8000/api/v1 && npm start"
    )
)
echo  %GREEN%[+] Platform is running!%RESET%
echo  %GREEN%[+] Dev API: http://localhost:8000/api/v1 ^| Dev UI: http://localhost:3000%RESET%
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

:: Step 0: Auto-build if needed
set "NODETRACE_DIR=%ROOT%NodeTrace\agents\python\dist\nodetrace-agent"
set "NODETRACE_EXE=%NODETRACE_DIR%\nodetrace-agent.exe"
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

echo  %YELLOW%[*] Stopping any previously running host agents...%RESET%
taskkill /f /im nodetrace-agent.exe 2>nul
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"name='java.exe'\" | Where-Object { $_.CommandLine -like '*aegis-guard*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" 2>nul
ping -n 3 127.0.0.1 >nul

:: Clean stale agent state so registration is fresh (all known token/pid locations)
if exist "%ROOT%token.json" del /q /f "%ROOT%token.json" 2>nul
if exist "%ROOT%nodetrace.pid" del /q /f "%ROOT%nodetrace.pid" 2>nul
if exist "%ROOT%NodeTrace\agents\python\token.json" del /q /f "%ROOT%NodeTrace\agents\python\token.json" 2>nul
if exist "%NODETRACE_DIR%\token.json" del /q /f "%NODETRACE_DIR%\token.json" 2>nul
if exist "%NODETRACE_DIR%\nodetrace.pid" del /q /f "%NODETRACE_DIR%\nodetrace.pid" 2>nul
if exist "%ROOT%aegis-guard\secret.json" del /q /f "%ROOT%aegis-guard\secret.json" 2>nul
if exist "%ROOT%logs" rmdir /s /q "%ROOT%logs" >nul 2>&1
mkdir "%ROOT%logs" 2>nul

echo  %YELLOW%[*] Checking Docker backend is running (http://localhost:8000)...%RESET%
cmd /c curl -s -o nul http://localhost:8000/ >nul 2>&1
if !errorlevel! neq 0 (
    echo  %RED%[!] Backend is not reachable at http://localhost:8000. Start it first with option [1].%RESET%
    call :maybe_pause
    goto menu_or_exit
)
echo  %GREEN%[+] Backend reachable.%RESET%

:: Read enroll key once, reuse for both agents
for /f "tokens=1,2 delims==" %%A in ('findstr /b "AGENT_ENROLL_KEY=" "%ROOT%.env" 2^>nul') do set "ENV_KEY=%%B"
if not defined ENV_KEY set "ENV_KEY=aegis-enroll-e17f250567d35991aadc5e60"

set "AEGIS_ENROLL_KEY=!ENV_KEY!"

:: Override HTTPS defaults for local dev (agents connect directly to brain, bypassing Caddy)
set "NODETRACE_BASE=http://localhost:8000/api/v1"
set "NODETRACE_REGISTER_URL=%NODETRACE_BASE%/register"
set "NODETRACE_UPDATE_URL=%NODETRACE_BASE%/update"
set "NODETRACE_HEARTBEAT_URL=%NODETRACE_BASE%/heartbeat"
set "AEGIS_BRAIN_URL=%NODETRACE_BASE%"
set "AEGIS_GATEWAY_URL=%NODETRACE_BASE%/telemetry/report"
set "AEGIS_SCAN_INTERVAL_MS=10000"

:: ---- NodeTrace Agent ----
set "NODETRACE_TOKEN_FILE=%NODETRACE_DIR%\token.json"
copy /y "%ROOT%NodeTrace\agents\python\run-agent.bat" "%NODETRACE_DIR%\run-agent.bat" >nul 2>&1
set "PYTHONUNBUFFERED=1"
echo  %YELLOW%[*] Starting NodeTrace Agent...%RESET%
start "NodeTrace Agent" /B cmd /c "set AEGIS_ENROLL_KEY=!ENV_KEY! && "%NODETRACE_DIR%\run-agent.bat"" > "%ROOT%logs\nodetrace.txt" 2>&1
echo  %GREEN%  [+] NodeTrace Agent started (log: logs\nodetrace.txt)%RESET%
ping -n 6 127.0.0.1 >nul
findstr /i /c:"Device registered" /c:"re-enrolled" /c:"Initial telemetry sent" "%ROOT%logs\nodetrace.txt" >nul 2>&1
if !errorlevel! neq 0 (
    echo  %RED%  [!] NodeTrace may have failed to register. Check logs\nodetrace.txt%RESET%
) else (
    echo  %GREEN%  [+] NodeTrace registration/telemetry confirmed in log.%RESET%
)

:: ---- Guard Agent ----
if not exist "!GUARD_JAR!" (
    echo  %RED%[!] Aegis-Guard JAR not found after build. Run [B]uild manually.%RESET%
    goto :after_guard
)

echo  %YELLOW%[*] Starting Aegis-Guard (Java) EDR Agent...%RESET%

:: Detect bundled JRE (check jre-new first, then jre, then system java)
set "JAVA_CMD="
if exist "%ROOT%aegis-guard\jre-new\bin\java.exe" set "JAVA_CMD=%ROOT%aegis-guard\jre-new\bin\java.exe"
if not defined JAVA_CMD if exist "%ROOT%aegis-guard\jre\bin\java.exe" set "JAVA_CMD=%ROOT%aegis-guard\jre\bin\java.exe"
if not defined JAVA_CMD set "JAVA_CMD=java"

start "Aegis-Guard Agent" /B cmd /c "cd /d "%ROOT%aegis-guard" && set "AEGIS_SCAN_INTERVAL_MS=10000" && "!JAVA_CMD!" -jar target\aegis-guard.jar > "%ROOT%logs\guard.txt" 2>&1"
echo  %GREEN%  [+] Aegis-Guard Agent started (log: logs\guard.txt)%RESET%
echo.

:after_guard
echo  %GREEN%[+] Host agents launched.%RESET%
echo  %GREEN%  Logs: logs\nodetrace.txt, logs\guard.txt%RESET%
call :maybe_pause
goto menu_or_exit

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

:maybe_pause
if /i "%AEGIS_BATCH%"=="1" exit /b 0
pause
exit /b 0

:menu_or_exit
if not "%~1"=="" exit /b 0
goto menu
