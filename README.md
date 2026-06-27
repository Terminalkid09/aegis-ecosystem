# Aegis XDR / SIEM Ecosystem

Aegis is a local XDR/SIEM lab made of four main services:

| Component | Stack | Role |
| --- | --- | --- |
| `aegis-brain` | FastAPI, SQLAlchemy, PostgreSQL, Redis | API, auth, telemetry processing, rules, alerts, VaultX, AI/OSINT endpoints |
| `aegis-link` | Spring Boot | Agent/syslog ingestion gateway; pushes events to Redis |
| `aegis-guard` | Java | Endpoint security agent and mitigation command consumer |
| `NodeTrace` | Python | Host telemetry agent for CPU/RAM/process/users/network flows |
| `frontend` | React | Dashboard for alerts, agents, rules, VaultX, OSINT and AI |

## Architecture

```text
Endpoints / Syslog
       |
       v
Aegis-Link  ---> Redis queue/cache ---> Aegis-Brain ---> PostgreSQL
                                           |
                                           v
                                      React Dashboard
```

## Quick Start

1. Copy the example environment file:

```cmd
copy .env.example .env
```

2. Change the security values in `.env` before using anything beyond local development:

```env
AEGIS_API_KEY=replace-with-a-long-random-value
AGENT_ENROLL_KEY=replace-with-a-long-random-value
JWT_SECRET=replace-with-at-least-32-random-characters
MASTER_KEY_B64=base64-encoded-32-byte-key
REDIS_PASSWORD=replace-with-a-long-random-value
```

Generate `MASTER_KEY_B64` with:

```cmd
openssl rand -base64 32
```

3. Start the platform:

```cmd
docker compose up -d --build
```

4. Open:

- Dashboard: `http://localhost:3000`
- Brain API: `http://localhost:8000`
- Link health: `http://localhost:8080/actuator/health`

On Windows you can also use:

```cmd
aegis.bat
```

## Authentication Model

- **Dashboard**: Bearer JWT after `POST /api/v1/auth/login` or register. Telemetry, rules, VaultX, OSINT (live), and AI require JWT.
- **Agents**: enrollment key at registration, then per-agent Bearer token (NodeTrace) or gateway API key (Aegis-Link).
- **Aegis-Link**: `X-Api-Key` for event ingestion — server-side only, not exposed to the React app.

The global `AEGIS_API_KEY` is for Aegis-Link and automation scripts. It does **not** grant dashboard access.

## Database

`aegis-brain` runs `alembic upgrade head` on startup. The repository includes an initial Alembic revision under `aegis-brain/alembic/versions`.

There is still an optional development fallback, `DB_BOOTSTRAP_CREATE_ALL=true`, that creates missing tables from SQLAlchemy metadata. Leave it disabled in production and use Alembic revisions for schema changes.

## Redis

Redis is password-protected in Docker Compose and all services are configured to use the same `REDIS_PASSWORD`.

If you run Redis outside Compose, make sure `REDIS_URL`, `REDIS_PASSWORD`, and `SPRING_DATA_REDIS_PASSWORD` all point to the same authentication setup.

## Agents

Containerized `aegis-guard` is behind the optional Compose profile:

```cmd
docker compose --profile container-agents up -d --build
```

For real endpoint telemetry, run agents on the host:

```cmd
cd NodeTrace\agents\python
python agent.py
```

```cmd
cd aegis-guard
mvn clean package -DskipTests
java -jar target\aegis-guard.jar
```

## Features

### Discovery Center
- **Network scan**: ARP + ICMP sweep + TCP connect scan — finds ALL devices on subnet, not just those with open ports
- **MAC vendor lookup**: OUI database identifies device manufacturers (Samsung, Apple, Cisco, etc.)
- **Agent status per IP**: `guard_status` and `nodetrace_status` columns show which agents are deployed/active on each host
- **Auto-deploy**: One-click agent deployment via WinRM (Windows) or SSH (Linux) using credentials stored in VaultX with `#deploy-creds` tag
- **Synchronize agent status**: Button to sync DiscoveredHost agent states with live Agent table

### Detection Rules Engine
- **MITRE ATT&CK metadata**: Each static rule carries tactic, technique, and technique ID (T1059, T1134, T1036, etc.)
- **Custom rules**: AND/OR multi-condition rules, whitelist (hostname/IP exclusions), auto-remediation actions
- **Rule testing**: `POST /api/v1/rules/test` to test rules against sample event data

### OSINT + AI Automation
- **Auto-enrichment**: When an alert fires, IPs/domains in the alert context are automatically looked up via VirusTotal, Shodan, AbuseIPDB
- **AI threat reports**: Ollama generates structured threat analysis with confidence score and recommended actions
- **Auto IP reputation**: OSINT results update the IP reputation database automatically

### Real-time Updates
- **WebSocket push**: Dashboard receives live updates every 500ms via `/api/v1/ws/overview`
- **Sub-second telemetry**: Guard agent pushes events as they happen via persistent WebSocket connection
- **Smooth charts**: Recharts AreaChart with Brush zoom, disabled animations for real-time data

### Demo Agent Tag
- Demo agents are tagged `is_demo: true`, excluded from main stats by default
- Yellow "DEMO" badge in Endpoints list
- Toggle to show/hide demo agents
- `?include_demo=true` query parameter to include them in API responses

### VaultX (Encrypted Notes)
- Tag-based credential lookup: notes with `#deploy-creds` tag and target IP are auto-discovered by Deployment Center
- Used for WinRM/SSH auto-deploy credentials

### Agent Architecture
- **Aegis-Guard (Java)**: Process monitoring, event reporting, command execution (KILL_PROCESS), heartbeat
- **NodeTrace (Python)**: Full telemetry (CPU/RAM/disk/network/processes/users/flows), WebSocket-ready

## API Endpoints

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /api/v1/auth/register` | none | Create dashboard user |
| `POST /api/v1/auth/login` | none | Get JWT |
| `GET /api/v1/telemetry/stats` | Bearer JWT | Dashboard counters (supports `?include_demo=true`) |
| `GET /api/v1/telemetry/agents` | Bearer JWT | Agent inventory (supports `?include_demo=true`) |
| `GET /api/v1/telemetry/alerts` | Bearer JWT | Alert list with filtering |
| `GET /api/v1/telemetry/threat-reports` | Bearer JWT | AI-generated threat analysis reports |
| `GET /api/v1/telemetry/remediations` | Bearer JWT | Auto-remediation action history |
| `GET /api/v1/telemetry/recent` | Bearer JWT | Recent NodeTrace telemetry |
| `GET /api/v1/rules/` | Bearer JWT | List custom detection rules |
| `POST /api/v1/rules/` | Bearer JWT | Create custom detection rule |
| `GET /api/v1/rules/static` | Bearer JWT | List static MITRE ATT&CK rules |
| `POST /api/v1/discovery/scan` | Bearer JWT | Network scan (CIDR, ports, ARP + ICMP sweep) |
| `GET /api/v1/discovery/hosts` | Bearer JWT | List discovered hosts (vendor, MAC, agent status) |
| `POST /api/v1/discovery/deploy` | Bearer JWT | Auto-deploy agent via WinRM/SSH |
| `POST /api/v1/discovery/sync-agent-status` | Bearer JWT | Sync agent deployment states |
| `POST /api/v1/osint/ip/{ip}` | Bearer JWT | IP reputation lookup (VT, Shodan, AbuseIPDB) |
| `GET /api/v1/ws/overview` | Bearer JWT (query param) | WebSocket live dashboard updates |
| `POST /register` | enrollment key | NodeTrace compatibility registration |
| `POST /update` | agent Bearer token | NodeTrace telemetry upload |

## Security Notes

This project is safe for local development only until these production tasks are complete:

- Replace every default secret in `.env`.
- For production, use `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` to avoid exposing Postgres/Redis ports.
- Store JWTs in a safer browser session model than long-lived `localStorage` tokens.
- Use incremental Alembic migrations for all schema changes (migrations are idempotent).
- Keep `AEGIS_LOG_LEVEL=INFO` or stricter in production.

Use this software only on systems where you have explicit permission.
