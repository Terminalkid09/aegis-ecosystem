@echo off
setlocal enabledelayedexpansion
title Aegis NodeTrace Agent Installer
color 0B

echo =======================================================
echo           AEGIS NODETRACE AGENT INSTALLER
echo =======================================================

echo [1/3] Checking Python installation...
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.11+ and try again.
    pause
    exit /b 1
)

cd /d "%~dp0\NodeTrace"

echo [2/3] Setting up Python virtual environment...
if not exist "venv" (
    python -m venv venv
)
call venv\Scripts\activate.bat
pip install -r requirements.txt

echo [3/3] Setting up configuration...
if not exist ".env" (
    if exist ".env.example" (
        copy .env.example .env >nul
        echo [INFO] Created .env from .env.example. Please edit it with your credentials.
    ) else (
        echo [WARN] .env.example not found. Please create .env manually.
    )
)

echo =======================================================
echo          INSTALLATION COMPLETE
echo =======================================================
echo To run the agent, use: start_nodetrace.bat
pause
