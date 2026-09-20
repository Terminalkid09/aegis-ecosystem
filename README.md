<h1 align="center">Aegis Ecosystem</h1>
<p align="center">
  <strong>Open-Source XDR / SIEM Platform</strong><br/>
  Endpoint detection &amp; response, multi-source SIEM ingestion, Sigma rules, SOAR playbooks and OSINT enrichment — in one local-first stack.
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#agents--telemetry">Agents</a> •
  <a href="#api-endpoints">API</a> •
  <a href="#security-notes">Security</a> •
  <a href="#development">Development</a>
</p>

<p align="center">
  <a href="https://github.com/Terminalkid09/aegis-ecosystem/actions/workflows/ci.yml"><img src="https://github.com/Terminalkid09/aegis-ecosystem/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/python-3.12-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/java-21-orange?style=flat-square&logo=openjdk&logoColor=white" alt="Java 21" />
  <img src="https://img.shields.io/badge/spring%20boot-3-6DB33F?style=flat-square&logo=spring&logoColor=white" alt="Spring Boot" />
  <img src="https://img.shields.io/badge/react-19-61dafb?style=flat-square&logo=react&logoColor=white" alt="React 19" />
  <img src="https://img.shields.io/badge/postgres-16-4169E1?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL 16" />
  <img src="https://img.shields.io/badge/redis-7-DC382D?style=flat-square&logo=redis&logoColor=white" alt="Redis 7" />
  <img src="https://img.shields.io/badge/platform-windows%20%7C%20linux-brightgreen?style=flat-square" alt="Cross-platform" />
</p>

---

## Overview

**Aegis** is an open-source, local-first XDR/SIEM platform for security labs, pilots and small teams. It combines endpoint agents, kernel-level telemetry (eBPF on Linux, ETW on Windows), multi-source log ingestion, deterministic detection with Sigma and custom rules, MITRE ATT&CK mapping, automated SOAR remediation and OSINT/AI enrichment into a single, cohesive product — deployed with **one command**.

| Area | Capabilities |
|------|-------------|
| **Endpoint (XDR)** | Guard (Java) + NodeTrace (Python) agents: process lineage, persistence, masquerading, security-control tampering; 9 remediation actions (kill, quarantine, isolate, sinkhole…) |
| **Kernel telemetry** | eBPF probes on Linux (`sched_process_exec`, TCP via ringbuf, verified 300/300 events on kernel 6.6); ETW kernel providers on Windows (user-mode consumer, no driver, no signing) |
| **SIEM ingestion** | Syslog (RFC 3164/5424), Windows Event Log, Zeek, Suricata, nginx/Squid, pfSense/iptables — one pipeline, parser auto-detection, real UDP/TCP listener |
| **Detection** | 21 static rules with MITRE mapping, custom AND/OR rules, **Sigma engine** (modifiers, mapping, fail-loud exclusions), threshold + sequence correlation over Redis windows |
| **Noise control** | Risk policy before `db.add(alert)`: **trusted-signed suppression** (signed IDE/browser/updater binaries from user-writable paths become log-only, S004/S009/S010/S012/S014), severity **decoupled from confidence** (weak-confidence hits score as LOW in the cumulative engine), and **triage muting**: resolving an alert silences that exact pattern on that host for 7 days — re-opening clears it |
| **SOAR** | 12 playbook action types with trigger conditions, execution history, composite `eradicate` chain |
| **Static analysis** | Aegis Total: PE/ELF/Mach-O/Office/PDF/archives/APK/LNK… with YARA, entropy, imports, IOCs and disassembly — nothing is rejected, everything is analyzed |
| **FIM** | Per-agent file integrity monitoring watchlist (Run keys, tasks, services, hosts, cron, systemd) via WatchService + SHA-256 baseline |
| **OSINT + AI** | VirusTotal/Shodan/AbuseIPDB auto-enrichment; pluggable AI provider (Ollama local / Gemini / OpenAI) chosen from the dashboard, with data-exit control |
| **Notifications** | Telegram alerts + heartbeat (works fully local), browser notifications, realtime alert WebSocket |
| **Interop** | OCSF 1.4.0 export (Detection Finding / Process Activity, JSON/NDJSON), structured event search, audit trail, Prometheus + Grafana profile |

> **Honest scope.** Detection is deterministic (signatures + heuristics + anomalies, no ML). Zeek/Suricata/Squid/pfSense sources are demonstrated with synthetic real-format samples (`scripts/siem_demo.py`), not production traffic. Single-node by design; HA overlay documents scale-readiness.

---

## Features

### 🛡️ Endpoint Detection & Response

| Module | Description |
|--------|-------------|
| **Static rules** | 21 deterministic rules: process lineage, masquerading, suspicious paths, persistence (Run keys, tasks), AV/Defender tampering, event-log clearing, recovery destruction. `GET /api/v1/rules/static` is the live source of truth |
| **MITRE ATT&CK** | Every rule and alert carries tactic, technique and technique ID (T1059, T1134, T1036, T1562, T1070.001, T1490…); badges link to the ATT&CK pages |
| **Custom rules** | AND/OR multi-condition rules, hostname/IP whitelists, auto-remediation actions, rule testing endpoint |
| **Remediation** | 9 agent commands — `KILL_PROCESS`, `KILL_PROCESS_TREE`, `BLOCK_IP`, `BLOCK_IP_TEMPORAL`, `QUARANTINE_BINARY`, `REMOVE_PERSISTENCE`, `DNS_SINKHOLE`, `COLLECT_IOC`, `ISOLATE_HOST` — plus `VERIFY` |
| **SOAR playbooks** | Trigger conditions on severity/event/process; automatic execution on matching alerts; 12 action types including composite `eradicate` (COLLECT_IOC → QUARANTINE → KILL_TREE → REMOVE_PERSISTENCE → VERIFY); full execution history |

### 📡 SIEM

| Module | Description |
|--------|-------------|
| **Log ingestion** | One pipeline for every source: `POST /api/v1/ingest/{source}` → parse → normalize → *same* detection → alert → SOAR chain used by agents. A log-raised alert triggers playbooks — one product, not two |
| **Parsers** | Auto-detected from payload shape: syslog (RFC 3164/5424), JSON/NDJSON, Windows Event (4624/4625/4688/4697/4720/7045/1102…), Zeek (conn/dns/http/ssl), Suricata `eve.json`, nginx/Squid/Apache, pfSense/iptables. `GET /api/v1/ingest/catalog` drives the UI |
| **Syslog listener** | Optional UDP **and** TCP listener (`SYSLOG_ENABLED`, default off, bound to `127.0.0.1` unless widened) — point rsyslog or a firewall straight at the brain; bounded queue, storms are counted and dropped, never accumulated |
| **Sigma engine** | Industry-standard YAML rules: field mapping, modifier expansion (`contains`, `startswith`, `re`, `all`, `base64`, `cidr`…), compiled into executable rules. A rule with an unsupported feature is **excluded and reported**, never half-executed (`GET /api/v1/ingest/detection-coverage`); 14 bundled community-style rules |
| **Correlation** | Threshold (`N events in T`: brute-force, port sweep, denied burst) and sequence (`A then B`: failed logins then success) over Redis-backed sliding windows; hits become normal alerts with MITRE mapping; windows and tracked entities are explicitly bounded |
| **Event store & search** | Monthly-partitioned storage (retention = partition `DROP`, not mass `DELETE`); structured search on an **allowlist** of fields with escaped free text — no client-controlled SQL ever reaches the database |
| **Source health** | `GET /api/v1/ingest/sources` exposes last event, unparsed count and last error per source — a silent source is visible, not invisible |

### 🧪 Static Analysis — Aegis Total

| Module | Description |
|--------|-------------|
| **Formats** | No extension is rejected: PE/.NET, ELF, Mach-O (incl. fat), Office OLE + OOXML (VBA macros, DDE, Excel 4.0, embedded MZ), PDF (JavaScript, OpenAction, Launch, XFA), ZIP/tar/gzip/bzip2/xz, APK/JAR/WASM, RTF, LNK, SQLite/pcap, plain scripts |
| **Every upload analyzed** | Unknown binaries still get magic identification, entropy, strings, IOC/secret scanning — never a bare "binary, score 10" |
| **YARA inside** | Uploaded samples are scanned with the active SOC signatures (yara-python); a match raises the score by fact — the report shows the matched rule and strings |
| **Bounded by design** | Per-entry and total-uncompressed caps, nesting depth, member count, text-scan windows — an adversarial archive cannot stall the worker |
| **Privacy** | Binaries are never stored: only sha256, findings and IOCs; reports are deletable (GDPR) |

### 📁 File Integrity Monitoring

| Module | Description |
|--------|-------------|
| **Watchlists** | Per-agent configuration from the dashboard: Run keys, Scheduled Tasks, services, hosts file, cron, systemd |
| **Engine** | Guard uses `WatchService` + SHA-256 baselines; every change becomes an OCSF File Activity event with MITRE mapping (T1543/T1547) |
| **Honest limits** | User-mode telemetry (not a minifilter driver); hashing capped at 8 MB/file; missing `yara64.exe` degrades with an explicit ack, never a silent "looks fine" |

### 🌐 OSINT + AI Automation

| Module | Description |
|--------|-------------|
| **Auto-enrichment** | IPs/domains in alert context are looked up via VirusTotal, Shodan, AbuseIPDB; results update the IP reputation database automatically |
| **Keys from the dashboard** | Settings → Integrations: providers are discovered dynamically from the backend catalog, keys encrypted at rest (KEK), effective immediately. An env var **wins** over the DB so ops can pin a key per deployment. Fallback: env → DB → skipped with `api_key_not_configured` (never a hard failure) |
| **AI providers** | `auto` \| `disabled` \| `ollama` \| `gemini` \| `openai` — chosen from the dashboard, no `.env` edit, no restart. `auto` uses what actually responds (Ollama probe → cloud keys → disabled); a dead endpoint never becomes an error stream |
| **Data-exit control** | `AI_AUTOMATIC_ENRICH`, default **off**: with a cloud provider, alert context (anonymized: IPs/emails/tokens redacted) leaves the network only when you switch it on. Local Ollama is always on, because nothing leaves the machine |
| **Deterministic core** | Detection does **not** depend on AI at any point: rules, Sigma, correlation, FIM and YARA are deterministic. AI only summarizes |

### 🔔 Notifications

| Channel | Description |
|---------|-------------|
| **Telegram** | Alerts at or above your chosen minimum severity (INFO → CRITICAL, default HIGH) pushed to a bot chat the moment they are created, plus a periodic "Aegis is alive" heartbeat — the dashboard does not need to be open. Outbound HTTPS only: a fully local stack needs no open ports, no port forwarding, no cloud host. Setup: `@BotFather` → paste the whole token (`123456789:ABC...`) in **Settings → Integrations & API Keys** → **Detect chat ID** in **Settings → Telegram Notifications** lists the chats that messaged your bot → **Send test message** verifies for real. Delivery is best-effort and fail-soft: detection and storage never depend on it |
| **Browser** | *Desktop Notifications* and *Audio Alarms* toggles are functional — native OS notifications (Notification API) and audio alerts (WebAudio), driven by the realtime stream |
| **Realtime stream** | `/api/v1/ws/alerts` pushes every newly created alert to connected dashboards (HttpOnly-cookie auth, no tokens in URLs); alert lists and counters update instantly |

### 🗺️ Discovery Center

| Module | Description |
|--------|-------------|
| **Network scan** | ARP + ICMP sweep + TCP connect scan — finds ALL devices on the subnet, not just those with open ports |
| **MAC vendor lookup** | OUI database identifies device manufacturers (Samsung, Apple, Cisco…) |
| **Agent status per IP** | `guard_status` / `nodetrace_status` show which agents are deployed and active on each host |
| **Signed one-line enrollment** | `POST /api/v1/deploy/token` issues a short-lived token for Guard, NodeTrace, or both; the installer downloads artifacts, registers Windows services / systemd units, enables restart recovery and consumes one slot per agent. Credential-based WinRM/SSH deployment was **removed** (HTTP 410), not disabled |

### 🔐 VaultX (Encrypted Notes)

| Module | Description |
|--------|-------------|
| **AES-256-GCM notes** | Decrypted only for authorized roles, every read audited. Generic secret storage for runbooks, tokens, recovery codes. Aegis never requests or stores remote-deploy credentials: deployment uses signed enrollment |

### ⚙️ Platform

| Module | Description |
|--------|-------------|
| **Realtime overview** | `/api/v1/ws/overview` pushes counters every 30s; agents push telemetry over HTTPS with an encrypted local spool and bounded retry |
| **Audit log** | Every API action (login, resolve, rule change, deploy) recorded with user, IP and details; non-blocking by design; dashboard viewer |
| **Bulk triage** | Resolve-all / delete-all with confirmation dialog, audit-logged |
| **Rate limiting** | SlowAPI backed by Redis; client key from `X-Forwarded-For` only behind a trusted proxy — a spoofed header cannot reset the budget; per-account login throttle, per-user AI limits |
| **Backups** | Compressed `pg_dump` every 6h via the `aegis-backup` profile service, 7-day retention |

---

## Quick Start

### One command (recommended)

Serve **Docker Desktop running** and **Python 3.10+**. Nothing else to start: the `.env` (random secrets), agent builds if missing, stack startup, admin bootstrap and smoke test are all guided by the same command.

```bash
git clone https://github.com/Terminalkid09/aegis-ecosystem.git
cd aegis-ecosystem
python scripts/setup.py
```

It prints the admin credentials, the dashboard URL and the update path. To update later (data preserved — the database volume is never touched):

```bash
python scripts/setup.py update          # rebuild + restart, DB preserved
python scripts/setup.py update --rebuild-agents   # also recompile host agents
```

**Requirements, honestly:**

| Needed | When |
|---|---|
| Docker Desktop (running) + Python 3.10+ | always (`setup.py` preflight stops and says so if missing) |
| JDK 21+ and Maven | only if agent artifacts don't exist and must be built (Windows: `build.bat` is invoked for you) |
| `nssm.exe` | **downloaded by `setup.py`** with pinned SHA-256 — used to install agents as Windows services |
| `yara64.exe` | **downloaded by `setup.py`** with pinned SHA-256 — used for on-endpoint YARA scans |

Both binaries are not in the repo (`.exe` is gitignored): the setup downloads and hash-verifies them (on the archive and again on the extracted executable). Offline or on a hash mismatch the install **continues** and declares exactly what stays off, with the manual command. `--skip-binaries` skips the download.

The `.bat` files are **not** a required step: `aegis.bat` is a convenience menu (start/stop/logs/build) for development. Local AI does not start by default: `set AEGIS_WITH_AI=1` before `setup.py` to enable Ollama.

### Docker (manual)

```bash
git clone https://github.com/Terminalkid09/aegis-ecosystem.git
cd aegis-ecosystem
copy .env.example .env        # cp on Linux/macOS
# edit .env: replace every placeholder secret
docker compose up -d --build
```

| Service | URL |
|---------|-----|
| **Dashboard** | `http://localhost:3000` |
| **Brain API** | `http://localhost:8000` |
| **Link health** | `http://localhost:8080/actuator/health` |

### Deployment profiles

| Profile | Command | Notes |
|---|---|---|
| **Lab** (default) | `docker compose up -d --build` | internal TLS, localhost ports |
| **Pilot** | `docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.mtls.yml up -d --build` | mTLS on :8443, requires real `.env` secrets + `BACKUP_PASSPHRASE` |
| **Observability** | `docker compose -f docker-compose.yml -f docker-compose.observability.yml --profile observability up -d --build` | Prometheus `:9090` + Grafana `:3001`, requires `GRAFANA_ADMIN_PASSWORD` |

Equivalent installers: `./install.sh lab|pilot [--observability]` and `.\install.ps1 lab|pilot [-Observability]` (never combined with pilot).

### Quality gates

```bash
# Brain tests (740+ pytest, deterministic, DB-backed)
python scripts/run_integration_tests.py --import-mode=importlib

# Guard tests (134 JUnit)
cd aegis-guard && mvn -B test

# NodeTrace unit tests
cd NodeTrace/agents/python && python -m unittest tests.test_ebpf tests.test_update tests.test_linux_probe

# Frontend: typecheck, build, browser e2e
cd frontend && npx tsc -b && npm run build && npm run e2e

# Live batteries: enroll → benign → attacks → resolve, and a hard evasion battery
python scripts/live_battery.py
python scripts/hard_battery.py
```

Four independent verification layers: 740+ pytest, 134 JUnit, 11 Playwright e2e, 2 live detection batteries — all green in CI.

---

## Architecture

Aegis is built as a set of small services that speak one event model.

### High-Level Architecture

```
 Endpoints / Syslog sources
   │                │
   │ agents         │ raw logs (rsyslog, firewall, proxy…)
   ▼                ▼
┌──────────┐   ┌──────────┐
│  Guard   │   │  NodeTrace│        ┌─────────────────────┐
│  (Java)  │   │ (Python) │──────▶ │      Aegis-Link      │
└────┬─────┘   └──────────┘        │   (Spring Boot)      │
     │                             │ ingest gateway, mTLS │
     │        enrollment, commands, PKI                 │
     ▼                             └──────────┬──────────┘
┌───────────────────────────────────┐           │
│           Aegis-Brain (FastAPI)   │      Redis (queue/cache)
│  telemetry → detection → alerts   │◀──────────┘
│  Sigma · correlation · SOAR · FIM │           │
│  YARA · Total · OSINT · AI        │           ▼
│  search · OCSF export · audit     │      PostgreSQL
└───────────────┬───────────────────┘   (partitioned event store)
                │
                ▼
        ┌──────────────┐        ┌──────────────────────────┐
        │   Dashboard   │        │ Optional: Prometheus +   │
        │  (React 19)   │        │ Grafana · Ollama (AI) ·  │
        │  ws realtime  │        │ Caddy (TLS, mTLS)        │
        └──────────────┘        └──────────────────────────┘
```

**Topology.** Each agent knows a single endpoint (`AEGIS_BRAIN_URL` for enrollment, commands and PKI; `AEGIS_GATEWAY_URL` for high-rate telemetry via `aegis-link`, which queues into Redis for the brain to consume). Dashboards are just browsers reading the brain: adding an operator is a registration, adding a host is an enrollment — agents never need to know about dashboards, and dashboards never talk to agents.

### Components

| Component | Stack | Role |
| --- | --- | --- |
| `aegis-brain` | FastAPI, SQLAlchemy, PostgreSQL, Redis | API, auth, telemetry processing, rules, alerts, VaultX, AI/OSINT, SOAR playbooks, syslog ingestion, audit logging |
| `aegis-link` | Spring Boot | Agent/syslog ingestion gateway; pushes events to Redis |
| `aegis-guard` | Java 21 | Endpoint security agent and mitigation command consumer |
| `NodeTrace` | Python | Host telemetry agent for CPU/RAM/process/users/network flows |
| `frontend` | React 19, TypeScript, Vite | Dashboard for alerts, agents, rules, VaultX, OSINT, AI, playbooks, syslog viewer, audit log |

---

## Agents & Telemetry

Every source enters the **same** event model and the **same** detection engine. Two roads converge, and the first requires no resident agent on the observed system.

| Layer | Where it runs | What it brings | Signing required |
|---|---|---|---|
| **eBPF** (`aegis-ebpf/`) | Linux, kernel | `sched_process_exec`, `do_exit`, TCP ESTABLISHED via ringbuf | no (kernel verifier) |
| **ETW kernel providers** (`aegis_etw.c`) | Windows, user-mode consumer | `Kernel-Process` 1/2, `Kernel-Network` TcpIp | no (system providers) |
| **Endpoint agents** | host | Guard (processes, persistence, services), NodeTrace (CPU/RAM/disk/network/users) | signed enrollment + mTLS |
| **Log sources** | appliance, server | syslog RFC5424/3164, Windows Event, Zeek, Suricata, nginx/Squid, firewall | none: one config line toward the endpoint |

On Linux, kernel telemetry is native (eBPF — 300/300 events verified without loss on kernel 6.6 with BTF). On Windows it runs through ETW: `aegis_etw.c` is a **user-mode** consumer of system providers (no driver, no signing), spawned by Guard itself and read from its stdout. It is **on by default** when the collector is present: `aegis.bat agents` (and the installer) compile or deploy `aegis-etw.exe`, point `AEGIS_ETW_PATH` at its absolute path and set `AEGIS_ETW_ALLOW_UNSIGNED=true` — the helper is built locally and carries no Authenticode signature, so Guard needs that explicit opt-in before executing it. The stream is **actually ingested**, not just probed: each kernel event enters the same enrichment pipeline as the poll (path, hash, Authenticode, command line) tagged `provenance=etw`, and the Toolhelp32 poll stays as the backstop (persistence, services, Defender, netstat) with a 15s dedup window so a process seen at kernel latency is not re-reported by the poll. If the collector is missing, Guard falls back to polling and **says so** (`quality=degraded:etw-…`): a missing capability, never a silent failure.

ETW requires a trace session, i.e. **administrative rights**: without them the collector prints the reason and exits, and Guard reports exactly that (`quality=degraded:etw-stream-StartTrace:_5_(serve_admin)`). So that a fresh clone needs no configuration, `aegis.bat agents` **asks for elevation once** (single UAC prompt; skip it with `set AEGIS_NO_ELEVATE=1`, or install Guard as a service — it runs as LocalSystem and needs no prompt at all). A proprietary kernel-mode driver is only needed for **inline prevention** — that requires EV signing and Microsoft attestation, and is out of scope together with ETW-TI.

### Agents survive reboot

Docker containers come back on their own (`restart: unless-stopped`), but host agents started by hand die with the session. Autostart is a property of the **installation**, not a manual step:

- **Both agents are Windows services (NSSM)** — `AegisGuard` and `AegisNodeTrace` — installed by their installers (`aegis-guard\install\windows\install.ps1`, `NodeTrace\install\windows\install.ps1`; elevated shell, auto-start, restart-on-crash, log file). Uninstall with the matching `uninstall.ps1`.
- **`python scripts/setup.py` registers them for you** when it runs elevated; if it is not elevated, it prints the exact commands instead of leaving a silent gap. Use `--no-autostart` to force dev-mode agents only (never two instances per endpoint: either services **or** dev processes).
- **No-admin fallback**: `powershell -ExecutionPolicy Bypass -File scripts/install-agents-autostart.ps1` registers Scheduled Tasks "at log on" (user context; elevated Guard actions unavailable). Remove with `-Remove`.
- **Token installer**: when remote dashboard connectivity is selected, the installer performs the service registration itself and verifies the service is running before returning success.

### Development mode (agents)

```bash
# NodeTrace
cd NodeTrace\agents\python
set AEGIS_ENROLL_KEY=<key>
set NODETRACE_REGISTER_URL=http://localhost:8000/api/v1/register
python agent.py
```

```bash
# Guard
cd aegis-guard
set AEGIS_BRAIN_URL=http://localhost:8000/api/v1
set AEGIS_GATEWAY_URL=http://localhost:8000/api/v1/telemetry/report
set AEGIS_ENROLL_KEY=<key>
jre-new\bin\java.exe -jar target\aegis-guard.jar
```

Two details that fail with unreadable errors:

- **A JVM 21+ is required**, and the `java` on the `PATH` is not automatically suitable: if it is an 8, the service installs, starts and dies with `UnsupportedClassVersionError`. The installer verifies the **version** and uses the resolved path, not the `java` string.
- **`AEGIS_ENROLL_KEY` is mandatory** even when `secret.json` already exists: `Config.ENROLL_KEY` is read at startup with `getEnvOrThrow`, so without it the process exits immediately.

### Standalone agent builds

Pre-compiled agents ship without Python/JDK runtime dependencies:

| Agent | Build Tool | Output | Runtime |
|---|---|---|---|
| NodeTrace | PyInstaller | `NodeTrace/agents/python/dist/nodetrace-agent/nodetrace-agent.exe` | 15 MB (bundled) |
| Aegis-Guard | Maven + jlink | `aegis-guard/target/aegis-guard.jar` + `jre-new/` | 47 MB (minimal JRE) |

Build all agents with a single command: `build.bat`. If `JAVA_HOME` still points at a JRE 8, `mvn test` fails with a confusing `class file version 65.0 ... only recognizes up to 52.0` (stale classes) even though compile reports success — point it at a JDK 21+ first.

---

## Authentication Model

- **Dashboard**: Bearer JWT after `POST /api/v1/auth/login` (self-service register is disabled by default: with `ALLOW_OPEN_REGISTRATION=false` only an admin can create accounts). Telemetry, rules, VaultX, OSINT, AI, OCSF export and Aegis Total all require JWT.
- **Roles**: `ROLE_PERMISSIONS` in `app/core/deps.py` maps `viewer`/`user`/`auditor`/`responder`/`analyst`/`admin` to permissions. The role is read from the database on **every** request, so a change applies without re-login. Registration always creates a `user`: privilege is granted from a shell, never from an exposed API.

  ```bash
  docker exec aegis-brain python -m app.admin list
  docker exec aegis-brain python -m app.admin set-role <email> admin
  ```

  Without at least one `admin`, host isolation, deploy approval, rule and alert deletion and site assignment all return 403 by design. `set-role` refuses to demote the last remaining admin unless `--force` is given.
- **Agents**: enrollment key at registration, then per-agent Bearer token (NodeTrace) or gateway API key (Aegis-Link). NodeTrace validates that token once at startup with an authenticated call: if the brain rejects it (401) the agent re-enrolls, which is the brain's own recovery path — the same `device_id` is kept, and a **revoked** device is refused (403), so this is not a way back in. Its identity files (`token.json`, device key/certificate) are resolved against a **fixed absolute directory** (`NODETRACE_IDENTITY_DIR`, default: the agent's own folder), never the current working directory.
- **Aegis-Link**: `X-Api-Key` for event ingestion — server-side only, never exposed to the React app.

The global `AEGIS_API_KEY` is for Aegis-Link and automation scripts. It does **not** grant dashboard access.

### Session & device trust

| Capability | How it works |
|---|---|
| **Silent renewal** | `POST /api/v1/auth/refresh` renews the session cookie; the dashboard renews every 25 min and on window focus — an active user never sees the login page again |
| **Stay signed in** | Opt-in 30-day device trust: the `aegis_remember` cookie carries only an opaque token (the server keeps the SHA-256), **rotated on every use** — a stolen cookie replays exactly once. Silent re-login via `POST /api/v1/auth/remember` |
| **Trusted devices** | Settings → Trusted Devices lists every device with last-used and expiry; revoke individually. Logging out ends the trust — the model is GitHub's, not "forever sessions" |

---

## Database & Redis

`aegis-brain` runs `alembic upgrade head` on startup; revisions live under `aegis-brain/alembic/versions`. An optional development fallback, `DB_BOOTSTRAP_CREATE_ALL=true`, creates missing tables from SQLAlchemy metadata — leave it disabled in production and use Alembic revisions for schema changes.

Redis is password-protected in Docker Compose and all services use the same `REDIS_PASSWORD`. If you run Redis outside Compose, make sure `REDIS_URL`, `REDIS_PASSWORD` and `SPRING_DATA_REDIS_PASSWORD` all point to the same authentication setup.

---

## API Endpoints

Full reference — all endpoints are under `/api/v1` unless noted.

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /auth/register` | none (or admin if registration closed) | Create dashboard user (validated, rate-limited) |
| `POST /auth/login` | none | Get JWT (rate-limited + per-account throttle); `remember: true` issues a 30-day device-trust cookie |
| `POST /auth/refresh` | session cookie | Silent session renewal (new JWT + cookie, same user) |
| `POST /auth/remember` | `aegis_remember` HttpOnly cookie | Silent re-login from a trusted device; rotates the device token on every use |
| `GET /auth/devices` | Bearer JWT | List trusted devices with last-used timestamps |
| `DELETE /auth/devices/{id}` | Bearer JWT | Revoke a trusted device; its cookie dies at next use |
| `POST /auth/logout` | Bearer JWT | Blacklist token, clear cookie, end device trust |
| `GET /auth/me` | Bearer JWT | Current user profile (30/min) |
| `GET /users` · `PATCH /users/{id}` | `manage` (admin) | List accounts; enable/disable or change role (disabled = immediate lockout; last-active-admin protected, 409) |
| `GET /telemetry/stats` · `/agents` · `/alerts` | Bearer JWT | Dashboard counters, agent inventory, alert list (filtering, `?include_demo=true`) |
| `GET /telemetry/alerts/{id}` | Bearer JWT | Alert detail with telemetry, threat reports, remediations |
| `PATCH /telemetry/alerts/{id}/resolve` | `triage` / `respond` | Resolve single alert with optional kill-process |
| `POST /telemetry/alerts/resolve-all` · `DELETE /telemetry/alerts` | Bearer JWT | Bulk resolve / delete (audit-logged) |
| `GET /telemetry/threat-reports` · `/remediations` · `/recent` · `/activity` | Bearer JWT | AI threat reports, remediation history, recent telemetry, mixed timeline |
| `POST /telemetry/report` · `/report/batch` | X-Agent-Id + Bearer | Agent telemetry report(s) (creates alerts) |
| `POST /telemetry/heartbeat` · `GET /telemetry/commands` | X-Agent-Id + Bearer | Agent heartbeat; command queue (Redis) |
| `GET /rules/` · `POST /rules/` | Bearer JWT (operator) | Custom detection rules CRUD (regex safety-checked) |
| `GET /rules/static` · `POST /rules/test` | Bearer JWT | Static MITRE rules; test rules against sample events |
| `POST /rules/replay/import` | Bearer JWT | Score an external JSONL corpus (benign/suspicious/malformed) with the real engine |
| `GET /discovery/status` · `POST /discovery/scan` · `GET /discovery/hosts` | Bearer JWT | Network discovery (CIDR, ports, ARP + ICMP sweep) |
| `POST /discovery/deploy` | — | Removed (HTTP 410): use `POST /deploy/token` |
| `POST /deploy/token` | `deploy` | Issue a short-lived enrollment token for signed one-line install |
| `POST /discovery/sync-agent-status` | Bearer JWT | Sync discovered-host agent states |
| `GET /total/formats` · `POST /total/upload` | Bearer JWT | Aegis Total format catalog and sample analysis |
| `GET /ocsf/alerts` | Bearer JWT | Alerts as OCSF 1.4.0 Detection Findings (JSON or NDJSON `?download=true`) |
| `POST /ocsf/convert` · `GET /ocsf/schema` | Bearer JWT | Convert a single event to OCSF; mapping description for integrators |
| `GET /osint/ip/{ip}` · `/osint/domain/{domain}` | Bearer JWT | Reputation lookups (VT, Shodan, AbuseIPDB) with cache |
| `GET /ws/overview` · `GET /ws/alerts` | `aegis_token` cookie | WebSocket counters snapshot (30s); realtime alert push — no tokens in URLs |
| `POST /ai/chat` · `GET /ai/threads` · `GET|PUT /ai/settings` · `GET /ai/status` | Bearer JWT | AI chat with prompt-injection detection; threads; provider/model selection; effective status |
| `GET /soar/playbooks` · `POST` · `PUT /{id}` · `DELETE /{id}` | Bearer JWT | SOAR playbook CRUD |
| `GET /soar/playbook-executions` | Bearer JWT | Playbook execution history |
| `GET /syslog/events` | Bearer JWT | Query syslog events (severity, hostname, app filter) |
| `POST /ingest/{source}` · `POST /ingest/test` | Bearer JWT / API key | Ingest raw logs (parsed + normalized + detected); parser dry-run — nothing stored |
| `GET /ingest/catalog` · `/sources` · `/stats` · `/detection-coverage` | Bearer JWT | Parser catalog; source health (last event, unparsed, last error); ingestion stats (EPS, by source/severity); loaded vs executable Sigma/correlation rules + exclusions |
| `POST /ingest/sources` | `operator` | Register a log source |
| `POST /search/events` · `GET /search/events` · `/fields` · `/stats` | Bearer JWT | Structured search (allowlisted fields, escaped text); shareable-link variant; searchable fields; event statistics |
| `GET /audit/logs` | Bearer JWT | Audit log entries |
| `POST /enroll/enroll` · `POST /register` · `POST /update` | enrollment key / agent token | Agent enrollment; NodeTrace compatibility registration; telemetry upload |
| `POST /vault/notes` · `GET` · `GET /{id}` · `DELETE /{id}` | Bearer JWT | Encrypted notes CRUD (AES-256-GCM) |
| `GET /telegram/settings` · `PUT` · `POST /telegram/test` · `POST /telegram/detect` | Bearer JWT (`manage` for writes) | Telegram notification config, live test message, and chat-id discovery via getUpdates |

---

## Configuration

Key environment variables (full list in `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `AEGIS_API_KEY` | placeholder | Gateway/automation API key (never grants dashboard access) |
| `AGENT_ENROLL_KEY` | placeholder | Agent enrollment key |
| `JWT_SECRET` | placeholder | Session signing secret (≥ 32 chars) |
| `MASTER_KEY_B64` | placeholder | Base64 32-byte KEK for encrypted settings (integration keys, VaultX) |
| `POSTGRES_PASSWORD` / `REDIS_PASSWORD` | placeholder | Service credentials (required by compose) |
| `DEBUG` | `false` | SQL echo and dev validations — must stay `false` in production |
| `ALLOW_OPEN_REGISTRATION` | `false` | Self-service registration (the brain refuses invalid production combos) |
| `COOKIE_SECURE` | `true` | Secure flag on auth cookies — set `false` only for local HTTP |
| `SYSLOG_ENABLED` | `false` | UDP/TCP syslog listener (binds `127.0.0.1` unless `SYSLOG_BIND` widened) |
| `AI_PROVIDER` / `AI_MODEL` | `auto` / `""` | AI provider and model (dashboard wins unless explicitly pinned here) |
| `AI_AUTOMATIC_ENRICH` | `false` | Automatic alert enrichment toward a **cloud** provider |
| `AEGIS_WITH_AI` | unset | Set `1` to add the Ollama service to the stack |
| `OLLAMA_URL` | in-stack | Point at a powerful LAN machine to keep AI local with big models |
| `AEGIS_ETW_ENABLED` | `true` when the collector exists | Spawns the ETW kernel collector from Guard |
| `AEGIS_ETW_PATH` | absolute path set by the launcher | Must be **absolute**: Guard refuses to execute a collector resolved from a writable workdir (hijack) |
| `AEGIS_ETW_ALLOW_UNSIGNED` | `true` for locally built collectors | Allows an unsigned helper. Keep `false` if you sign `aegis-etw.exe` and want signature enforcement |
| `AEGIS_NO_ELEVATE` | unset | `1` stops `aegis.bat agents` from requesting the UAC prompt for kernel telemetry |
| `NODETRACE_IDENTITY_DIR` | agent directory | Where `token.json` and the device key/certificate live. Resolved as an **absolute** path on purpose: with a relative path the same device used a different identity per launch directory, and the brain answered 401 to every authenticated call |
| `PLAYBOOK_SCRIPT_ENABLED` | `false` | Shell `script` SOAR actions (keep off unless enterprise-approved) |
| `RATE_LIMIT_STORAGE_URI` | memory | `redis://…` for multi-worker/HA rate limiting |

---

## Security Notes

This project is designed for local security labs and development. Before production use:

- Replace every default secret in `.env`.
- Set `DEBUG=false` and `ALLOW_OPEN_REGISTRATION=false` (the brain refuses to start otherwise); for enterprise also `ENTERPRISE_STRICT=true` with `MTLS_MODE=required` (refused at startup if missing).
- Keep playbook `script` actions disabled (`PLAYBOOK_SCRIPT_ENABLED=false`, default) unless enterprise-approved: they execute shell on the server.
- For production, use `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` to avoid exposing Postgres/Redis ports.
- Replace Caddy `tls internal` with proper TLS certificates (Let's Encrypt).
- Use incremental Alembic migrations for all schema changes (migrations are idempotent).
- Keep `AEGIS_LOG_LEVEL=INFO` or stricter in production.
- **Remember-me is done defensively**: opaque token + server-side SHA-256, rotated on every use, scoped to the auth paths, behind the same origin/CSRF gate as the session cookie, listed and revocable from the dashboard.

Use this software only on systems where you have explicit permission.

---

## Pilot & Enterprise Readiness

```bash
# OS preflight (Windows) / sh scripts/os-preflight.sh (Linux)
powershell -ExecutionPolicy Bypass -File scripts/os-preflight.ps1

# Dev-tool preflight (python/node/java/docker/ports)
python scripts/dev_preflight.py

# Detection replay on 3 independent splits (training/validation/regression)
python scripts/replay_report.py --all

# Threshold calibration report (synthetic panel, not fleet baseline)
python scripts/calibrate_thresholds.py

# API smoke against the live stack
python scripts/api_smoke.py [--base http://127.0.0.1:8000]

# Pilot soak: N synthetic agents for T seconds (dev DB only)
python scripts/pilot_soak.py --agents 10 --duration 300

# Browser E2E (needs: npm i, playwright chromium, live stack)
cd frontend && npm run e2e

# Full audit: machine JSON + human report
python scripts/audit_report.py
```

| Item | Path |
|---|---|
| OS validation procedures + status | `docs/os-validation/` |
| HA runbook + overlay | `docs/HA.md`, `docker-compose.ha.yml` |
| Benchmark method + numbers | `docs/BENCHMARK.md` |
| Operations (profiles, secrets, PKI) | `docs/OPERATIONS.md` |
| Threat model | `docs/THREAT_MODEL.md` |

Production profile: `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` (requires `BACKUP_PASSPHRASE`; Postgres/Redis not published). The HA overlay adds resource limits and scale-readiness (`--scale aegis-brain=2`).

---

## Development

### Project Structure

```
aegis-ecosystem/
├── aegis-brain/             # FastAPI brain: API, detection, SIEM, SOAR, Total
│   ├── app/api/v1/          # REST endpoints (auth, telemetry, ingest, search…)
│   ├── app/services/        # telemetry, sigma, correlation, notifier, total
│   ├── app/rules/           # static rules + Sigma engine
│   ├── alembic/versions/    # DB migrations
│   └── tests/               # 740+ pytest (CI-verified)
├── aegis-link/              # Spring Boot ingestion gateway
├── aegis-guard/             # Java endpoint agent (processes, FIM, remediation)
│   └── install/windows/     # NSSM service installer/uninstaller
├── NodeTrace/               # Python telemetry agent
│   └── agents/python/       # PyInstaller standalone build
├── aegis-ebpf/              # eBPF probes (Linux) + ETW collector (Windows)
├── frontend/                # React 19 / TypeScript dashboard
│   ├── src/components/      # pages, common widgets
│   ├── src/hooks/           # realtime WS, session renewal, notifications
│   └── e2e/                 # Playwright browser tests
├── scripts/                 # setup.py, batteries, preflights, audit tools
├── docs/                    # operations, HA, benchmarks, threat model
├── docker-compose*.yml      # lab / prod / mTLS / observability / HA overlays
└── .github/workflows/       # CI: lint, tests, secret scan, Trivy, SBOM
```

### CI/CD

GitHub Actions runs on every push: lint (flake8 + ESLint), secret scanning, event-contract checks, Windows installer checks, OS-compat matrix (ubuntu + windows), brain + guard + frontend tests, pip-audit, Trivy image scanning (strict on images we build, informational on upstream images), and SBOM generation. Release jobs run on tags.

---

<p align="center">
  <strong>Authorized use only.</strong> Aegis is a defensive security platform intended for<br/>
  systems you own or have explicit written permission to monitor.
</p>

<p align="center">
  Built with ❤️ by <a href="https://github.com/Terminalkid09">Terminalkid09</a>
</p>
