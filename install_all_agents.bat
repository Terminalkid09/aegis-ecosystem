@echo off
setlocal enabledelayedexpansion
title Aegis Agents Master Installer
color 0B

echo =======================================================
echo           AEGIS AGENTS MASTER INSTALLER
echo =======================================================
echo This script will install all Aegis host agents:
echo 1. NodeTrace (Python Agent)
echo 2. Aegis Guard (Java Agent)
echo.
pause

echo.
echo [1/2] Installing NodeTrace Agent...
call "%~dp0\install_nodetrace.bat"

echo.
echo [2/2] Installing Aegis Guard Agent...
call "%~dp0\install_guard.bat"

echo.
echo =======================================================
echo          ALL AGENTS INSTALLED SUCCESSFULLY
echo =======================================================
echo You can now run the agents using their respective start scripts.
pause
