@echo off
setlocal
cd /d "%~dp0"

if not defined AEGIS_ENROLL_KEY (
    if defined AGENT_ENROLL_KEY set "AEGIS_ENROLL_KEY=%AGENT_ENROLL_KEY%"
)
if not defined NODETRACE_REGISTER_URL set "NODETRACE_REGISTER_URL=http://localhost:8000/api/v1/register"
if not defined NODETRACE_UPDATE_URL set "NODETRACE_UPDATE_URL=http://localhost:8000/api/v1/update"
if not defined NODETRACE_HEARTBEAT_URL set "NODETRACE_HEARTBEAT_URL=http://localhost:8000/api/v1/heartbeat"
if not defined NODETRACE_TOKEN_FILE set "NODETRACE_TOKEN_FILE=%~dp0token.json"
set "PYTHONUNBUFFERED=1"

nodetrace-agent.exe
