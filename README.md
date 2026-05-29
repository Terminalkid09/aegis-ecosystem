# Aegis XDR Ecosystem 🛡️

[![GitLab CI](https://gitlab.com/Terminalkid09/aegis-ecosystem/badges/main/pipeline.svg)](https://gitlab.com/Terminalkid09/aegis-ecosystem/-/pipelines)
![Java Version](https://img.shields.io/badge/Java-21-orange?logo=openjdk)
![Python Version](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.3.5-brightgreen?logo=spring-boot)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115.5-009688?logo=fastapi)

**Aegis XDR Ecosystem** is a production-ready Modular Monolith platform for Extended Detection and Response. It unifies high-performance telemetry ingestion, statistical anomaly detection, AI-driven forensics, and military-grade data encryption into a single, cohesive architecture.

## 🌟 Key Innovations

- **Modular Monolith Architecture**: Unlike fragmented legacy systems, Aegis-Brain centralizes all intelligence (Heuristics, AI, OSINT, VaultX) into a unified Python core with clear domain boundaries, reducing operational overhead while maintaining extreme scalability.
- **Unified Secure Enrollment**: Replaced shared API keys with a secure per-agent enrollment flow. Every agent performs a "First Boot" registration to receive unique, revocable credentials.
- **VaultX (Envelope Encryption)**: Implements AES-256-GCM encryption where user data is protected by per-user Data Encryption Keys (DEK), which are themselves encrypted by a Master Key Encryption Key (KEK).
- **Enterprise Async Pipeline**: 100% non-blocking database (SQLAlchemy 2.0/asyncpg) and Redis (asyncio) operations, capable of handling enterprise-level telemetry throughput.
- **AI-Suite Security Guardian**: Integrated LLM analysis with built-in **Prompt Injection Protection** and Redis-backed rate limiting to ensure safe and reliable security assistance.

## Architecture Overview

| Component | Technology | Responsibility |
| :--- | :--- | :--- |
| `aegis-guard` | Java 21, Maven | **Defense Agent**. Focuses on security event monitoring (process creation) and executes active mitigation commands (`KILL_PROCESS`). |
| `aegis-link` | Spring Boot 3.3.5 | **Secure Gateway**. Validates agent identities via Redis and enqueues security events for analysis. |
| `aegis-brain` | FastAPI, Python 3.12 | **Modular Monolith Core**. Correlates data, runs heuristic/statistical engines, and provides AI Forensics. |
| `NodeTrace` | Python Agent | **Telemetry Agent**. Specializes in performance monitoring (CPU, RAM, Disk) and reports metrics for anomaly detection. |
| `Postgres` | Postgres 16-alpine | Persistent store for alerts, registered agents, and encrypted VaultX data. |
| `Redis` | Redis 7-alpine | High-speed cache for authentication, async event queues, and rate-limiting. |
| `Dashboard` | React 18.2.0 | Unified XDR interface for real-time visualization, forensics, and response management. |

## Data Flow

1. `aegis-guard` (Security) and `NodeTrace` (Telemetry) capture system data and send it to the gateway.
2. `aegis-link` validates the agent identity and enqueues data to Redis.
3. `aegis-brain` consumes events asynchronously, applying specialized detection rules.
4. The dashboard reads correlated alerts and forensics from the Brain via async APIs.
5. `aegis-brain` issues mitigation commands back to `aegis-guard` for threat resolution.

## Detection & Intelligence Engines

| Engine | Source Agent | Responsibility |
| :--- | :--- | :--- |
| **Heuristic Engine** | `aegis-guard` | Analyzes process events for known threats (`mimikatz`), suspicious execution paths, and privilege escalation. |
| **Anomaly Engine** | `NodeTrace` | Applies Z-Score statistical analysis to identify anomalous system behavior (e.g., unexpected CPU spikes). |
| **AI Forensics** | Both | Uses LLMs to explain the context of security events and correlated performance anomalies. |
| **SentinelX (OSINT)**| INTEL | Automated tracking and reputation lookups via Shodan and AbuseIPDB providers. |

## Installation & Deployment

### Prerequisites
- Docker and Docker Compose
- Java 21 for native `aegis-guard` execution
- Python 3.12 for `aegis-brain` development

### 1. Configure .env
A `.env` file is required in the root. Scripts will generate one automatically if missing.

Required Security Values:
- `AGENT_ENROLL_KEY`: Token for first-time agent registration.
- `MASTER_KEY_B64`: 32-byte Base64 key for military-grade VaultX encryption.
- `JWT_SECRET`: Secure string for user session authentication.
- `DATABASE_URL`: Connection string for Postgres (asyncpg).

### 2. Start all services
Use the unified workspace launcher:
- **Windows**: `.\aegis-cli.bat`
- **Linux/macOS**: `./aegis-cli.sh`

Both scripts orchestrate the full Docker stack and the React dashboard.

### 3. Run host agents
Agents should run on the host when you want real host telemetry and process visibility. Docker Compose no longer starts them by default; containerized agents are available only with the `container-agents` profile for demos.

We provide **Double-Click Installers** for Windows to automatically set up the host agents:
- `install_nodetrace.bat`: Sets up the Python virtual environment and dependencies for NodeTrace.
- `install_guard.bat`: Compiles the Java Spring Boot agent via Maven.
- `install_all_agents.bat`: Master installer to set up everything automatically.

Once installed, start the agents individually:
```bat
start-aegis-guard-host.bat
start-nodetrace-host.bat
```
Or start both simultaneously:
```bat
start-host-agents.bat
```

For demo-only container agents:
```bash
docker compose --profile container-agents up -d --build
```

## API Reference (V1)

| Endpoint | Method | Responsibility |
| :--- | :--- | :--- |
| `/api/v1/enroll/enroll` | `POST` | Secure agent registration using `ENROLL_KEY`. |
| `/api/v1/telemetry/report`| `POST` | Authenticated ingestion of system telemetry and metrics. |
| `/api/v1/ai/chat` | `POST` | AI Security Assistant interaction (rate-limited & protected). |
| `/api/v1/vault/notes` | `GET/POST`| Management of AES-256-GCM encrypted user notes. |
| `/api/v1/vault/notes/{id}` | `DELETE` | Delete an encrypted note owned by the current user. |
| `/api/v1/telemetry/alerts`| `GET` | Centralized alert feed for the Dashboard. |
| `/api/v1/telemetry/agents`| `GET` | Registered agent inventory, including agent type. |
| `/api/v1/telemetry/stats`| `GET` | Dashboard totals and unresolved severity breakdown. |
| `/api/v1/osint/ip/{ip}` | `GET` | OSINT intelligence lookup for a specific target. |
| `/api/v1/osint/domain/{domain}` | `GET` | Domain OSINT compatibility lookup. |
| `/api/v1/osint/history` | `GET` | Recent OSINT query history. |

Agent telemetry endpoints require per-agent bearer credentials after enrollment. Dashboard management endpoints use `X-Api-Key`; user-scoped AI, VaultX, and live OSINT scans require a user JWT.

## Legal Disclaimer

Use this software only on systems where you have explicit permission. The maintainers are not responsible for unauthorized use, damage, or legal consequences.

## Author

**Terminalkid09** – [GitHub](https://github.com/Terminalkid09)