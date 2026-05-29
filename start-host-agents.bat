@echo off
setlocal
cd /d "%~dp0"

echo [INFO] Aegis Ecosystem Host Agent Launcher
echo [WARN] Ensure the Aegis Brain stack is running before starting agents.
echo [INFO] Brain API expected at: http://localhost:8000
echo.

echo [INFO] Starting host agents in separate windows...
start "Aegis Guard Host Agent" cmd /k "%~dp0start-aegis-guard-host.bat"
start "NodeTrace Host Agent" cmd /k "%~dp0start-nodetrace-host.bat"

echo [SUCCESS] Host agent launch requested.
echo [INFO] Keep both opened terminal windows running while monitoring this host.
