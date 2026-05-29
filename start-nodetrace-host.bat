@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo [INFO] Starting NodeTrace on host...

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python is required.
    pause
    exit /b 1
)

echo [INFO] Verifying dependencies...
python -m pip install -r NodeTrace\agents\python\requirements.txt >nul 2>&1

cd NodeTrace\agents\python
python agent.py
