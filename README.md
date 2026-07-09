# Aegis XDR / SIEM Ecosystem

Aegis is a local XDR/SIEM lab made of four main services:

| Component | Stack | Role |
| --- | --- | --- |
| `aegis-brain` | FastAPI, SQLAlchemy, PostgreSQL, Redis | API, auth, telemetry processing, rules, alerts, VaultX, AI/OSINT, SOAR playbooks, syslog ingestion, audit logging |
| `aegis-link` | Spring Boot | Agent/syslog ingestion gateway; pushes events to Redis |
| `aegis-guard` | Java | Endpoint security agent and mitigation command consumer |
| `NodeTrace` | Python | Host telemetry agent for CPU/RAM/process/users/network flows |
| `frontend` | React | Dashboard for alerts, agents, rules, VaultX, OSINT, AI, playbooks, syslog viewer, audit log |

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

Or use the all-in-one management script (Windows):

```cmd
aegis.bat
```

Menu: `[1]` Start Backend + Frontend, `[2]` Start Local Agents, `[3]` Stop, `[4]` Clean DB, `[5]` View Logs, `[6]` Exit, `[B]` Build.

### Standalone Agent Builds

Pre-compiled agents ship without Python/JDK runtime dependencies:

| Agent | Build Tool | Output | Runtime |
|---|---|---|---|
| NodeTrace | PyInstaller | `NodeTrace/agents/python/dist/nodetrace-agent/nodetrace-agent.exe` | 15 MB (bundled) |
| Aegis-Guard | Maven + jlink | `aegis-guard/target/aegis-guard.jar` + `jre-new/` | 47 MB (minimal JRE) |

Build all agents with a single command:

```cmd
build.bat
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

For real endpoint telemetry, run standalone agents on the host:

```cmd
aegis.bat
:: Option [2] — Start Local Agents
```

Or run with `aegis.bat start agents` in batch mode.

### Development Mode (requires Python/Java)

```cmd
cd NodeTrace\agents\python
set AEGIS_ENROLL_KEY=<key>
set NODETRACE_REGISTER_URL=http://localhost:8000/api/v1/register
python agent.py
```

```cmd
cd aegis-guard
set AEGIS_BRAIN_URL=http://localhost:8000/api/v1
java -jar jre-new/bin/java.exe -jar target\aegis-guard.jar
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
- **NodeTrace (Python)**: Telemetry sensor — collects CPU/RAM/disk/network/processes/users/flows and reports to Aegis-Brain. Does NOT perform remediation. Polls commands for `GET_TELEMETRY` and `NETWORK_SCAN` only.
- **Aegis-Guard (Java)**: Endpoint security agent — monitors running processes, detects suspicious activity via process monitoring hooks (ProcessMonitor), applies detection rules with MITRE ATT&CK metadata, and executes remediation commands. Polls commands for all 9 remediation actions.
- **Available remediation commands**:
  | Command | Description | Windows | Linux |
  |---|---|---|---|
  | `KILL_PROCESS` | Terminate single process | `taskkill /F /PID` | `ProcessHandle.destroyForcibly()` |
  | `KILL_PROCESS_TREE` | Kill process + children | `taskkill /F /T /PID` | `children().forEach(destroyForcibly)` |
  | `BLOCK_IP` | Permanent firewall block | `netsh advfirewall` rule | `iptables -A INPUT -s IP -j DROP` |
  | `BLOCK_IP_TEMPORAL` | Time-limited block (auto-expire via `ScheduledExecutorService`) | same + scheduled unblock | same + scheduled unblock |
  | `QUARANTINE_BINARY` | Copy binary to `quarantine/` dir, SHA256 hash, ACL-restrict | `icacls /deny Everyone` | `setReadable/Executable(false)` |
  | `REMOVE_PERSISTENCE` | Scan & remove Registry Run keys, Scheduled Tasks, Services, Startup folder, cron, systemd, shell init | `reg delete`, `schtasks /delete`, `sc stop/delete` | crontab scan, systemd scan |
  | `DNS_SINKHOLE` | Redirect domain to `0.0.0.0` via hosts file | `%SystemRoot%\drivers\etc\hosts` | `/etc/hosts` |
  | `COLLECT_IOC` | Forensics: path, SHA256, netstat conns, command line | `wmic`, `netstat -ano` | `/proc/pid/*`, `ss -tupn` |
  | `VERIFY` | Check if PID is alive | `ProcessHandle.of(pid).isPresent()` | same |
  | `ISOLATE_HOST` | Isolate endpoint from network | (platform-specific) | (platform-specific) |

### SOAR Playbook Engine
- **Trigger conditions**: Evaluate alert severity, event type, and process name before executing actions
- **Action types**:
  | Action Type | Target | Description |
  |---|---|--|
  | `webhook` | URL | HTTPS POST with alert payload |
  | `block_ip` | IP address | Permanent firewall block via agent |
  | `block_ip_temporal` | IP address | Time-limited firewall block (default 3600s, configurable via `duration_seconds` param) |
  | `kill_process` | — | Terminate single process by PID |
  | `kill_process_tree` | — | Terminate process + all child processes |
  | `quarantine_binary` | — | Copy executable to `quarantine/` dir + ACL-restrict permissions |
  | `remove_persistence` | — | Scan & remove Registry Run keys, scheduled tasks, services, cron, systemd units |
  | `dns_sinkhole` | Domain | Add domain to hosts file (`0.0.0.0`) |
  | `collect_ioc` | — | Gather executable path, SHA256, netstat connections, command line |
  | `isolate_host` | — | Isolate endpoint from network |
  | `script` | Command line | Local shell command execution |
  | `eradicate` | — | Composite chain: COLLECT_IOC → QUARANTINE → KILL_PROCESS_TREE → REMOVE_PERSISTENCE → VERIFY |
- **Automatic execution**: Playbooks matching alert conditions run automatically after alert creation
- **Playbook CRUD**: Create, edit, activate/deactivate playbooks via dashboard or API
- **Execution history**: Track each playbook run with timestamps, status, and results

### MITRE ATT&CK Alert Mapping
- **Alert enrichment**: Every alert carries `mitre_tactic_id`, `mitre_technique_id`, `mitre_tactic_name`, `mitre_technique_name`
- **Rule propagation**: MITRE fields from matched `CustomRule` are propagated to the resulting alert
- **Dashboard badges**: Alerts display clickable technique IDs linking to MITRE ATT&CK reference pages

### Syslog Event Viewer
- **Centralized storage**: Syslog events from Aegis-Link or external parsers stored in `SyslogEvent` table
- **Rich query API**: Filter by severity, facility, hostname, app name with pagination
- **Dashboard viewer**: Real-time syslog table with severity badges, hostname, and app-name columns

### Audit Log
- **Action tracking**: Every API action (login, alert resolve, rule change, deploy) is logged with user, IP, and details
- **Non-blocking**: `log_audit()` utility runs after the main commit — failures don't impact operations
- **Dashboard viewer**: Chronological audit log table with JSON detail expansion

### Resolve All / Delete All
- **Bulk alert management**: Resolve all unresolved alerts or delete all alerts with a single button
- **Confirmation dialog**: Prevents accidental mass operations
- **Audit logging**: Bulk operations are recorded in the audit log

### Rate Limiting
- **Per-endpoint limits**: `/auth/me` limited to 30 requests/minute per user via SlowAPI-compatible Redis limiter
- **AI chat**: Per-user rate limit for AI chat endpoint (configurable via `AI_RATE_LIMIT_PER_MIN`)

### CI/CD Pipeline
- **GitLab CI**: Automated lint (flake8 + ESLint), security audit (bandit), and test stages
- **Test isolation**: Dedicated `aegis_test` PostgreSQL database for test runs — never touches production data

### Database Backup
- **Automatic dumps**: `pg_dump` compressed backup every 6 hours via cron
- **Retention**: 7-day backup retention with daily rotation
- **Isolated service**: Docker Compose backup service (`aegis-backup`) on `backup` profile with dedicated volume

## API Endpoints

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /api/v1/auth/register` | none | Create dashboard user |
| `POST /api/v1/auth/login` | none | Get JWT |
| `POST /api/v1/auth/logout` | Bearer JWT | Blacklist token, clear cookie |
| `GET /api/v1/auth/me` | Bearer JWT | Current user profile (rate-limited 30/min) |
| `GET /api/v1/telemetry/stats` | Bearer JWT | Dashboard counters (supports `?include_demo=true`) |
| `GET /api/v1/telemetry/agents` | Bearer JWT | Agent inventory (supports `?include_demo=true`) |
| `GET /api/v1/telemetry/alerts` | Bearer JWT | Alert list with filtering |
| `GET /api/v1/telemetry/alerts/{id}` | Bearer JWT | Alert detail with telemetry, threat reports, remediations |
| `POST /api/v1/telemetry/alerts/resolve-all` | Bearer JWT | Resolve all unresolved alerts |
| `DELETE /api/v1/telemetry/alerts` | Bearer JWT | Delete all alerts |
| `PATCH /api/v1/telemetry/alerts/{id}/resolve` | Bearer JWT | Resolve single alert with optional kill-process |
| `GET /api/v1/telemetry/threat-reports` | Bearer JWT | AI-generated threat analysis reports |
| `GET /api/v1/telemetry/remediations` | Bearer JWT | Auto-remediation action history |
| `GET /api/v1/telemetry/recent` | Bearer JWT | Recent NodeTrace telemetry |
| `GET /api/v1/telemetry/activity` | Bearer JWT | Mixed timeline (telemetry + alerts) |
| `POST /api/v1/telemetry/report` | X-Agent-Id + Bearer | Agent telemetry report (creates alerts) |
| `POST /api/v1/telemetry/heartbeat` | X-Agent-Id + Bearer | Agent heartbeat |
| `GET /api/v1/telemetry/commands` | X-Agent-Id + Bearer | Agent command queue (Redis) |
| `GET /api/v1/rules/` | Bearer JWT | List custom detection rules |
| `POST /api/v1/rules/` | Bearer JWT | Create custom detection rule |
| `GET /api/v1/rules/static` | Bearer JWT | List static MITRE ATT&CK rules |
| `GET /api/v1/discovery/status` | Bearer JWT | Current scan status |
| `POST /api/v1/discovery/scan` | Bearer JWT | Network scan (CIDR, ports, ARP + ICMP sweep) |
| `GET /api/v1/discovery/hosts` | Bearer JWT | List discovered hosts (vendor, MAC, agent status) |
| `POST /api/v1/discovery/deploy` | Bearer JWT | Auto-deploy agent via WinRM/SSH |
| `POST /api/v1/discovery/sync-agent-status` | Bearer JWT | Sync agent deployment states |
| `GET /api/v1/osint/ip/{ip}` | Bearer JWT | IP reputation lookup (VT, Shodan, AbuseIPDB) with cache |
| `GET /api/v1/ws/overview` | Bearer JWT (query param) | WebSocket live dashboard updates |
| `POST /api/v1/ai/chat` | Bearer JWT | AI chat with prompt injection detection |
| `GET /api/v1/ai/threads` | Bearer JWT | List AI conversation threads |
| `DELETE /api/v1/ai/threads/{id}` | Bearer JWT | Delete AI thread |
| `GET /api/v1/soar/playbooks` | Bearer JWT | List SOAR playbooks |
| `POST /api/v1/soar/playbooks` | Bearer JWT | Create SOAR playbook |
| `PUT /api/v1/soar/playbooks/{id}` | Bearer JWT | Update SOAR playbook |
| `DELETE /api/v1/soar/playbooks/{id}` | Bearer JWT | Delete SOAR playbook |
| `GET /api/v1/soar/playbook-executions` | Bearer JWT | List all playbook execution history |
| `GET /api/v1/syslog/events` | Bearer JWT | Query syslog events (severity, hostname, app filter) |
| `GET /api/v1/audit/logs` | Bearer JWT | List audit log entries |
| `POST /api/v1/enroll/enroll` | enrollment key | Agent enrollment with key validation |
| `POST /api/v1/vault/notes` | Bearer JWT | Create encrypted note (AES-256-GCM) |
| `GET /api/v1/vault/notes` | Bearer JWT | List note titles (encrypted) |
| `GET /api/v1/vault/notes/{id}` | Bearer JWT | Read decrypted note |
| `DELETE /api/v1/vault/notes/{id}` | Bearer JWT | Delete note |
| `POST /register` | enrollment key | NodeTrace compatibility registration |
| `POST /update` | agent Bearer token | NodeTrace telemetry upload |

## Security Notes

This project is designed for local security labs and development. Before production use:

- Replace every default secret in `.env`.
- For production, use `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` to avoid exposing Postgres/Redis ports.
- Replace Caddy `tls internal` with proper TLS certificates (Let's Encrypt).
- Store JWTs in a safer browser session model than long-lived `localStorage` tokens.
- Use incremental Alembic migrations for all schema changes (migrations are idempotent).
- Keep `AEGIS_LOG_LEVEL=INFO` or stricter in production.

Use this software only on systems where you have explicit permission.

## Riferimenti

| Documento | Path |
|-----------|------|
| Guida moduli e test manuali | `docs/AEGIS_MODULE_GUIDE.md` |
| Report completamento | `docs/AEGIS_BRAIN_COMPLETION_REPORT.md` |
| Modifiche al codice | `docs/AEGIS_MODIFICHE_REPORT.md` |
| Feature report | `docs/AEGIS_FEATURE_REPORT.md` |
| Test report | `docs/AEGIS_TEST_REPORT.md` |
| Setup aegis-brain | `aegis-brain/SETUP.md` |
| Setup frontend | `frontend/README.md` |
