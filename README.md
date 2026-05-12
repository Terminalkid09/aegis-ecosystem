# Aegis EDR Ecosystem

[![CI Pipeline](https://github.com/Terminalkid09/aegis-ecosystem/actions/workflows/ci.yml/badge.svg)](https://github.com/Terminalkid09/aegis-ecosystem/actions/workflows/ci.yml)
![Java Version](https://img.shields.io/badge/Java-21-orange?logo=openjdk)
![Python Version](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.3.5-brightgreen?logo=spring-boot)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115.5-009688?logo=fastapi)

Aegis EDR Ecosystem is a modular detection, ingestion, and analysis stack for process telemetry. The repository includes an agent, a Redis-backed ingestion gateway, and a FastAPI-based analysis engine with a React frontend.

## Architecture Overview

| Component | Technology (versions) | Responsibility |
| :--- | :--- | :--- |
| `aegis-guard` | Java 21, Maven | Edge agent collecting `SystemEvent` records and forwarding them to `aegis-link`. |
| `aegis-link` | Spring Boot 3.3.5, Spring Data Redis | HTTP ingestion gateway; validates events and enqueues them to Redis. |
| `aegis-brain` | Python 3.12, FastAPI 0.115.5 | Analysis engine that consumes Redis events, applies heuristic detections, and stores alerts and agents in Postgres. |
| `Postgres` | Postgres 16-alpine | Persistent store for agents and alerts. |
| `Redis` | Redis 7-alpine | Event queue and command exchange. |
| `Dashboard` | React 18.2.0 | Frontend UI for alert and stats visualization (`frontend/`). |

## Data Flow

1. `aegis-guard` captures system events and sends them to `aegis-link`.
2. `aegis-link` validates the event and queues it in Redis.
3. `aegis-brain` consumes Redis events, applies heuristic rules, and writes alerts to Postgres.
4. The dashboard reads metrics and alerts from `aegis-brain`.
5. `aegis-brain` can issue commands back to agents through Redis.

## Detection Rules

| Rule Name | Severity | What it detects |
| :--- | :--- | :--- |
| `rule_known_attack_tool` | CRITICAL | Known attack tooling such as `mimikatz`, `psexec`, `netcat`, `cobalt_strike`. |
| `rule_double_extension` | HIGH | Deceptive double extensions like `.doc.exe`, `.pdf.bat`, `.jpg.js`. |
| `rule_suspicious_execution_path` | HIGH | Execution from suspicious directories like `%TEMP%`, `%APPDATA%`, `/tmp`, `/var/tmp`, or `/dev/shm`. |
| `rule_privilege_escalation` | HIGH | Desktop applications running with privileged accounts such as `SYSTEM`, `root`, or `Administrator`. |
| `rule_script_interpreter_abuse` | MEDIUM | Script interpreters such as `powershell`, `cmd`, `bash`, `python`, `wscript`, and `rundll32`. |
| `rule_encoded_command` | HIGH | Encoded commands in PowerShell or similar, indicating possible payload obfuscation. |
| `rule_network_tool` | MEDIUM | Network analysis tools executed from suspicious directories. |

## Installation & Deployment

### Prerequisites
- Docker and Docker Compose
- Java 21 for native `aegis-guard` execution
- Optional: Python 3.12 for `aegis-brain` development

### 1. Configure .env
A `.env` file is required in the repository root before starting services.

The repository includes `.env.example` for bootstrap. Both `aegis-cli.bat` and `aegis-cli.sh` will create `.env` from `.env.example` if the file is missing.

Required values:
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `POSTGRES_PORT` (default `5432`)
- `REDIS_PORT_EXTERNAL` (default `6379`)
- `LINK_PORT_EXTERNAL` (default `8080`)
- `AEGIS_API_KEY`
- `AEGIS_AGENT_ID`
- `AEGIS_SCAN_INTERVAL_MS` (default `1000`)
- `DATABASE_URL`

Example:
```env
POSTGRES_DB=aegis
POSTGRES_USER=aegis
POSTGRES_PASSWORD=change_me
POSTGRES_PORT=5432
REDIS_PORT_EXTERNAL=6379
LINK_PORT_EXTERNAL=8080
AEGIS_API_KEY=secret-key
AEGIS_AGENT_ID=agent-001
AEGIS_SCAN_INTERVAL_MS=1000
DATABASE_URL=postgresql://aegis:change_me@aegis-postgres:5432/aegis
```

`aegis-guard` also reads these environment variables from `Config.java`:
- `AEGIS_AGENT_ID`
- `AEGIS_GATEWAY_URL`
- `AEGIS_SCAN_INTERVAL_MS`

### 2. Start all services
Use the workspace launcher scripts to start backend and dashboard components together.

Windows:
```powershell
.\aegis-cli.bat
```

Linux/macOS:
```bash
./aegis-cli.sh
```

Both scripts run `docker-compose up -d --build` and attempt to start the frontend automatically.

Use `--stop` to shut down all services:

Windows:
```powershell
.\aegis-cli.bat --stop
```

Linux/macOS:
```bash
./aegis-cli.sh --stop
```

### 3. Run aegis-guard on host
If the agent should run outside Docker, build and start it. Note that the agent code expects `AEGIS_GUARD_API_KEY` for authentication.

```bash
cd aegis-guard
mvn clean package -DskipTests
# On Linux/macOS
export AEGIS_GUARD_API_KEY=secret-key
java -jar target/aegis-guard.jar

# On Windows (cmd)
set AEGIS_GUARD_API_KEY=secret-key
java -jar target/aegis-guard.jar
```

#### Native Installation (Service)
For production deployment, install `aegis-guard` as a system service.

**Windows (requires NSSM):**
1. Download NSSM from https://nssm.cc/.
2. Copy `win64/nssm.exe` (or `win32/nssm.exe`) into `aegis-guard/install/windows/`.

```powershell
cd aegis-guard/install/windows
.\install.ps1
```

This installs the agent as a Windows service named "AegisGuard".

**Linux (systemd):**
```bash
cd aegis-guard/install/linux
sudo ./install.sh
```

This installs the agent as a systemd service running as root.

**Security Notes:**
- The Linux service runs as root for full system visibility; ensure proper access controls.
- Scripts load environment variables from the workspace `.env` file; secure this file appropriately.
- Verify NSSM binary integrity before use.

## Service Ports

| Service | Port |
| :--- | :--- |
| `aegis-postgres` | `5432` |
| `aegis-redis` | `6379` |
| `aegis-link` | `8080` |
| `aegis-brain` | `8000` |
| `aegis-guard` | not exposed / internal only |

## API Reference

| Endpoint | Method | Notes |
| :--- | :--- | :--- |
| `/api/v1/events` | `POST` | Ingests agent events. `X-Agent-Id` header should match payload `agentId` when present. |
| `/api/v1/health` | `GET` | Health check for `aegis-link` and Redis queue status. |
| `/api/v1/commands` | `GET` | Agent command polling; requires `X-Agent-Id` header. |
| `/alerts` | `GET` | List alerts; supports `agent_id`, `severity`, `is_resolved`, `limit`, `offset`. |
| `/alerts/{alert_id}` | `GET` | Retrieve a single alert. |
| `/alerts/{alert_id}/resolve` | `PATCH` | Resolve an alert and enqueue mitigation commands when applicable. |
| `/agents` | `GET` | List registered agents. |
| `/stats` | `GET` | Aggregated alert counts and active agents. |

### Event payload fields
`SystemEvent` includes: `agentId`, `pid`, `processName`, `processPath`, `user`, `os`, `fileHash`, `eventType`, `timestamp`, `hostname`, `ipAddress`.

## Legal Disclaimer

Use this software only on systems where you have explicit permission. The maintainers are not responsible for unauthorized use, damage, or legal consequences.

## Author

**Terminalkid09** – [GitHub](https://github.com/Terminalkid09)