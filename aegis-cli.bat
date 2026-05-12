@echo off
setlocal enabledelayedexpansion

:: AEGIS CLI - Windows Management Script
:: Unified tool for start, stop and status

set APP_NAME=Aegis EDR Ecosystem
set FRONTEND_DIR=frontend
set DOCKER_COMPOSE=docker-compose.yml

:: Check for arguments
if "%1"=="--stop" goto :stop
if "%1"=="--status" goto :status

:start
cls
echo [INFO] Starting %APP_NAME%...

:: Check for .env file
if not exist .env (
    if exist .env.example (
        echo [WARN] .env file not found. Creating from .env.example...
        copy .env.example .env
        echo [IMPORTANT] Please edit .env with your configuration and restart.
        pause
        exit /b 1
    ) else (
        echo [ERROR] .env.example not found. Cannot continue.
        pause
        exit /b 1
    )
)

:: Check Docker
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not running. Please start Docker Desktop and try again.
    pause
    exit /b 1
)

:: Start Backend
echo [INFO] Launching backend services (Docker)...
docker-compose up -d --build
if %errorlevel% neq 0 (
    echo [ERROR] Failed to start Docker services.
    pause
    exit /b 1
)

:: Start Frontend
echo [INFO] Launching frontend dashboard...
cd %FRONTEND_DIR%
start "Aegis-Frontend" /B cmd /c "npm start"
cd ..

echo.
echo ==================================================
echo   %APP_NAME% IS NOW RUNNING
echo ==================================================
echo   - Dashboard: http://localhost:3000
echo   - Brain API: http://localhost:8000/docs
echo   - Link API:  http://localhost:8080/api/v1/health
echo ==================================================
echo.
echo Use 'aegis-cli.bat --stop' to shut down from another terminal.
echo.

:wait_prompt
echo [READY] All systems active.
echo Type 'stop' to shut down everything or press Ctrl+C twice.
set /p input="> "
if /I "!input!"=="stop" goto :stop
goto :wait_prompt

:stop
echo.
echo [INFO] Shutting down %APP_NAME%...
echo [INFO] Stopping Docker containers...
docker-compose -f %DOCKER_COMPOSE% down

echo [INFO] Cleaning up frontend processes...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :3000') do (
    taskkill /F /PID %%a 2>nul
)
taskkill /F /IM node.exe /T 2>nul

echo [SUCCESS] All services stopped.
if "%1"=="" pause
exit /b 0

:status
echo [INFO] Checking status of %APP_NAME%...
echo.
echo --- Docker Containers ---
docker-compose ps
echo.
echo --- Frontend Reachability ---
curl -s -I http://localhost:3000 | findstr "HTTP/1.1 200 OK" >nul
if %errorlevel% equ 0 (
    echo [OK] Frontend is UP (http://localhost:3000)
) else (
    echo [WARN] Frontend seems to be DOWN.
)
pause
goto :eof
