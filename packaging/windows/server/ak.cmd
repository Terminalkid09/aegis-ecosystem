@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0ak.ps1" %*
exit /b %ERRORLEVEL%
