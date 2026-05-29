@echo off
setlocal enabledelayedexpansion
title Aegis Guard Agent Installer
color 0B

echo =======================================================
echo           AEGIS GUARD AGENT INSTALLER
echo =======================================================

cd /d "%~dp0\aegis-guard"

call install_agent.bat

echo =======================================================
echo          INSTALLATION COMPLETE
echo =======================================================
pause
