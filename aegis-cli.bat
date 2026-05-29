@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

echo [INFO] Aegis XDR Ecosystem launcher

where docker >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Docker is not installed or not available in PATH.
    pause
    exit /b 1
)

docker compose version >nul 2>nul
if errorlevel 1 (
    where docker-compose >nul 2>nul
    if errorlevel 1 (
        echo [ERROR] Neither "docker compose" nor "docker-compose" is available.
        pause
        exit /b 1
    )
    set "COMPOSE=docker-compose"
) else (
    set "COMPOSE=docker compose"
)

if "%~1"=="--help" goto help
if "%~1"=="help" goto help
if "%~1"=="--stop" goto stop
if "%~1"=="stop" goto stop
if "%~1"=="--logs" goto logs
if "%~1"=="logs" goto logs

docker info >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Docker is installed, but the Docker daemon is not running.
    echo [INFO] Start Docker Desktop, wait until it is ready, then run "%~nx0" again.
    pause
    exit /b 1
)

if not exist ".env" (
    if not exist ".env.example" (
        echo [ERROR] .env is missing and .env.example was not found.
        pause
        exit /b 1
    )
    echo [INFO] Creating .env from .env.example...
    copy ".env.example" ".env" >nul
)

echo [INFO] Using compose command: !COMPOSE!
echo [INFO] Building and starting services...
call !COMPOSE! up -d --build
if errorlevel 1 (
    echo [ERROR] Docker Compose failed to start the stack.
    pause
    exit /b 1
)

echo [INFO] Waiting briefly for services to initialize...
timeout /t 5 /nobreak >nul

echo [INFO] Service status:
call !COMPOSE! ps

echo.
echo [SUCCESS] Ecosystem start requested.
echo [INFO] Dashboard: http://localhost:3000
echo [INFO] Brain API: http://localhost:8000/api/v1
echo [INFO] Link API: http://localhost:8080/api/v1/health
echo.
echo [TIP] Use "%~nx0 --logs" to follow logs, or "%~nx0 --stop" to stop the stack.
pause
exit /b 0

:stop
echo [INFO] Stopping Aegis XDR Ecosystem...
call !COMPOSE! down
if errorlevel 1 (
    echo [ERROR] Docker Compose failed to stop the stack.
    pause
    exit /b 1
)
echo [SUCCESS] Ecosystem stopped. Volumes were preserved.
pause
exit /b 0

:logs
echo [INFO] Following logs. Press CTRL+C to exit logs.
call !COMPOSE! logs -f
exit /b %errorlevel%

:help
echo.
echo Usage:
echo   %~nx0          Build and start the full Docker stack
echo   %~nx0 --stop   Stop the stack while preserving volumes
echo   %~nx0 --logs   Follow Docker Compose logs
echo   %~nx0 --help   Show this help
echo.
pause
exit /b 0
