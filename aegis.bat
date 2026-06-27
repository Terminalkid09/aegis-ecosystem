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

if /i "%~1"=="install" goto install
if /i "%~1"=="start" goto start_platform
if /i "%~1"=="ollama" goto start_with_ollama
if /i "%~1"=="agents" goto start_agents
if /i "%~1"=="stop" goto stop
if /i "%~1"=="clean" goto clean_db

:menu
cls
echo  %CYAN%========================================================================%RESET%
echo  %PURPLE%                    AEGIS SIEM / XDR COMMAND CENTER %RESET%
echo  %CYAN%========================================================================%RESET%
echo.
echo  %GREEN%[1]%RESET% Install Everything (Dependencies, NPM, Agents)
echo  %GREEN%[2]%RESET% Start Backend (Docker) + Frontend (npm start)
echo  %GREEN%[3]%RESET% Start Local Agents (NodeTrace ^& Aegis-Guard)
echo  %GREEN%[4]%RESET% Stop All Services (Docker)
echo  %GREEN%[5]%RESET% Clean Database (Wipes DB to apply new schemas)
echo  %GREEN%[6]%RESET% Start with Ollama ^(docker compose --profile ollama^)
echo  %RED%[7] Exit%RESET%
echo.
set /p choice="Select an option (1-7): "

if "%choice%"=="1" goto install
if "%choice%"=="2" goto start_platform
if "%choice%"=="3" goto start_agents
if "%choice%"=="4" goto stop
if "%choice%"=="5" goto clean_db
if "%choice%"=="6" goto start_with_ollama
if "%choice%"=="7" exit /b 0
goto menu

:install
echo.
echo  %CYAN%[*] Installing Frontend dependencies...%RESET%
cd /d "%ROOT%frontend" && call npm install
if errorlevel 1 exit /b 1

echo  %CYAN%[*] Installing Python dependencies for NodeTrace...%RESET%
cd /d "%ROOT%NodeTrace\agents\python" && call pip install -r requirements.txt
if errorlevel 1 exit /b 1

echo  %CYAN%[*] Compiling Java Aegis-Guard Agent...%RESET%
if exist "C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot\bin\javac.exe" (
    set "JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot"
    set "PATH=!JAVA_HOME!\bin;!PATH!"
)
cd /d "%ROOT%aegis-guard" && call mvn clean package -DskipTests
if errorlevel 1 exit /b 1

cd /d "%ROOT%"
echo  %GREEN%[+] Installation complete!%RESET%
call :maybe_pause
goto menu_or_exit

:start_platform
echo.
echo  %PURPLE%[*] Starting Aegis Backend (Docker Compose)...%RESET%
cd /d "%ROOT%"
call docker compose up -d
if errorlevel 1 exit /b 1

netstat -ano | findstr ":3000 " | findstr "LISTENING" >nul
if !errorlevel! equ 0 (
    echo  %YELLOW%[!] Port 3000 is already in use. Skipping local npm start.%RESET%
) else (
    if /i "%AEGIS_SKIP_FRONTEND_START%"=="1" (
        echo  %YELLOW%[!] AEGIS_SKIP_FRONTEND_START=1. Frontend launch skipped.%RESET%
    ) else (
        echo  %PURPLE%[*] Waiting for backend to initialize...%RESET%
        timeout /t 8 >nul
        echo  %CYAN%[*] Starting React Dashboard on http://localhost:3000...%RESET%
        start "Aegis Dashboard" cmd /k "cd /d "%ROOT%frontend" && npm start"
    )
)
echo  %GREEN%[+] Platform is running!%RESET%
echo  %GREEN%[+] API: http://localhost:8000 ^| Dashboard: http://localhost:3000%RESET%
call :maybe_pause
goto menu_or_exit

:start_with_ollama
echo.
echo  %PURPLE%[*] Starting full stack with Ollama...%RESET%
cd /d "%ROOT%"
call docker compose --profile ollama up -d
if errorlevel 1 exit /b 1

netstat -ano | findstr ":3000 " | findstr "LISTENING" >nul
if !errorlevel! equ 0 (
    echo  %YELLOW%[!] Port 3000 is already in use. Skipping local npm start.%RESET%
) else (
    if /i "%AEGIS_SKIP_FRONTEND_START%"=="1" (
        echo  %YELLOW%[!] AEGIS_SKIP_FRONTEND_START=1. Frontend launch skipped.%RESET%
    ) else (
        echo  %CYAN%[*] Starting React Dashboard...%RESET%
        start "Aegis Dashboard" cmd /k "cd /d "%ROOT%frontend" && npm start"
    )
)
echo  %GREEN%[+] Full stack running with Ollama AI!%RESET%
call :maybe_pause
goto menu_or_exit

:start_agents
echo.
echo  %YELLOW%[*] Checking Docker backend is running...%RESET%
curl -s -o nul http://localhost:8000/ >nul 2>&1
if !errorlevel! neq 0 (
    echo  %RED%[!] Backend is not reachable. Start it first with option [2].%RESET%
    call :maybe_pause
    goto menu_or_exit
)
echo  %GREEN%[+] Backend reachable.%RESET%

echo  %YELLOW%[*] Starting NodeTrace (Python) Telemetry Agent on host...%RESET%
start "NodeTrace Agent" /B /MIN cmd /c "cd /d "%ROOT%NodeTrace\agents\python" && python agent.py > "%ROOT%nodetrace.log" 2>&1"

if exist "%ROOT%aegis-guard\target\aegis-guard.jar" (
    echo  %YELLOW%[*] Starting Aegis-Guard (Java) EDR Agent on host...%RESET%
    set "JDK25=C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot\bin\java.exe"
    if exist "%ROOT%aegis-guard\jre\bin\java.exe" (
        set "JAVA_CMD=%ROOT%aegis-guard\jre\bin\java.exe"
    ) else (
        set "JAVA_CMD=!JDK25!"
    )
    start "Aegis-Guard Agent" /B /MIN cmd /c "cd /d "%ROOT%aegis-guard" && set AEGIS_ENROLL_KEY=aegis-enrollment-tokenFor_v3.0.0&& set AEGIS_BRAIN_URL=http://localhost:8000/api/v1&& set AEGIS_GATEWAY_URL=http://localhost:8000/api/v1/telemetry/report&& "!JAVA_CMD!" -jar target\aegis-guard.jar > "%ROOT%aegis-guard.log" 2>&1"
) else (
    echo  %YELLOW%[!] Aegis-Guard jar not found at aegis-guard\target\aegis-guard.jar. Run option [1] first.%RESET%
)

echo  %GREEN%[+] Host agents launched. Logs: nodetrace.log, aegis-guard.log%RESET%
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
