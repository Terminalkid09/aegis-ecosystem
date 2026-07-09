@echo off
REM AEGIS EDR Dashboard - Quick Start Script (Windows)
REM This script automates the installation and startup process

setlocal enabledelayedexpansion

echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║       AEGIS EDR Dashboard - Quick Start Installer              ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.

REM Check Node.js
echo 📦 Checking Node.js installation...
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed. Please install Node.js 14+ from https://nodejs.org
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('node --version') do set NODE_VERSION=%%i
echo ✅ Node.js !NODE_VERSION! found

REM Check npm
echo 📦 Checking npm installation...
where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ npm is not installed
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('npm --version') do set NPM_VERSION=%%i
echo ✅ npm !NPM_VERSION! found

REM Navigate to current directory
echo.
echo 📂 Setting up frontend directory...
cd /d "%~dp0"
echo ✅ Current directory: %cd%

REM Check if node_modules exists
if exist node_modules (
    echo ⚠️  node_modules directory already exists
    set /p REINSTALL="Reinstall dependencies? (y/n): "
    if /i "!REINSTALL!"=="y" (
        echo 🗑️  Removing old dependencies...
        rmdir /s /q node_modules
        if exist package-lock.json del package-lock.json
    )
) else (
    echo 📥 Installing dependencies...
    call npm install
    echo ✅ Dependencies installed
)

REM Create .env file if it doesn't exist
if not exist .env (
    echo.
    echo ⚙️  Creating .env file...
    copy .env.example .env >nul
    echo ✅ .env file created with default values
    echo    Backend URL: https://aegis.local/api/v1
    echo    Edit .env if your backend runs on a different address
) else (
    echo.
    echo ✅ .env file already exists
)

REM Check backend connectivity (using PowerShell if available)
echo.
echo 🔗 Checking backend connectivity...
where powershell >nul 2>nul
if %errorlevel% equ 0 (
    powershell -Command "try { [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $null = Invoke-WebRequest -Uri 'https://aegis.local/api/v1/telemetry/stats' -UseBasicParsing -TimeoutSec 2; Write-Host '✅ Backend is running and accessible' } catch { Write-Host '⚠️  Could not connect to backend at https://aegis.local (ensure hosts file has 127.0.0.1 aegis.local)' }"
) else (
    echo ⚠️  PowerShell not found, skipping backend check
)

REM Final instructions
echo.
echo ╔════════════════════════════════════════════════════════════════╗
echo ║                    Ready to Start! 🚀                          ║
echo ╚════════════════════════════════════════════════════════════════╝
echo.
echo 📌 Next Steps:
echo    1. Ensure aegis-brain backend is running via Docker (https://aegis.local)
echo    2. Ensure hosts file has: 127.0.0.1 aegis.local
echo    3. Run: npm start
echo    4. Dashboard: https://aegis.local (production) or http://localhost:3000 (dev)
echo.
echo 📚 Documentation:
echo    - README.md - Installation and feature guide
echo    - DEVELOPMENT.md - Architecture and development guide
echo    - INSTALLATION_CHECKLIST.md - Detailed verification steps
echo.
echo 💡 Quick Commands:
echo    npm start         - Start development server
echo    npm run build     - Build for production
echo    npm test          - Run tests (when available)
echo.
echo 🤔 Need help?
echo    Check DEVELOPMENT.md for troubleshooting
echo.

REM Ask if user wants to start now
set /p START_NOW="Start development server now? (y/n): "
if /i "!START_NOW!"=="y" (
    echo 🌐 Starting development server...
    call npm start
) else (
    echo.
    echo To start later, run: npm start
    pause
)
