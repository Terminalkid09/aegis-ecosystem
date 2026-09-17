# Aegis XDR / SIEM Ecosystem

Aegis is a local XDR/SIEM lab made of four main services:

| Component | Stack | Role |
| --- | --- | --- |
| `aegis-brain` | FastAPI, SQLAlchemy, PostgreSQL, Redis | API, auth, telemetry processing, rules, alerts, VaultX, AI/OSINT, SOAR playbooks, syslog ingestion, audit logging |
| `aegis-link` | Spring Boot | Agent/syslog ingestion gateway; pushes events to Redis |
| `aegis-guard` | Java | Endpoint security agent and mitigation command consumer |
| `NodeTrace` | Python | Host telemetry agent for CPU/RAM/process/users/network flows |
| `frontend` | React | Dashboard for alerts, agents, rules, VaultX, OSINT, AI, playbooks, syslog viewer, audit log |

**In a hurry?** → [Quick Start](#quick-start): one command, from clone to a working platform.

## Table of contents

- [Architecture](#architecture)
- [Quick Start](#quick-start) — install, update, requirements, profiles
- [Authentication Model](#authentication-model)
- [Database](#database) · [Redis](#redis) · [Agents](#agents)
- [Telemetry Collection Layers](#telemetry-collection-layers)
- [Features](#features) — detection, YARA/FIM, OSINT/AI, SOAR, SIEM, Aegis Total
- [API Endpoints](#api-endpoints)
- [Security Notes](#security-notes)
- [Pilot & Enterprise Readiness](#pilot--enterprise-readiness)
- [References](#references)

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

**Topology.** Each agent knows a single endpoint (`AEGIS_BRAIN_URL` for
enrollment, commands and PKI; `AEGIS_GATEWAY_URL` for high-rate telemetry via
`aegis-link`, which queues into Redis for the brain to consume). Dashboards are
just browsers reading the brain: adding an operator is a registration, adding a
host is an enrollment — agents never need to know about dashboards, and
dashboards never talk to agents.

## Quick Start

### From clone to a working platform (one command)

Serve **Docker Desktop in esecuzione** e **Python 3.10+**. Nient'altro per
partire: il `.env` (con segreti casuali), la build degli agenti se mancano,
l'avvio dello stack, il bootstrap dell'admin e lo smoke di verifica sono
guidati dallo stesso comando.

```cmd
git clone <repo> && cd aegis-ecosystem
python scripts/setup.py
```

Al termine stampa credenziali admin, URL della dashboard e i passi per
l'aggiornamento (`python scripts/setup.py update`, che **non tocca il
database**).

Honest notes on requirements:

| Serve | Quando |
|---|---|
| Docker Desktop (avviato) + Python 3.10+ | sempre (preflight di `setup.py`: se manca, si ferma e lo dice) |
| JDK 21+ e Maven, pip/PyInstaller | **solo** se gli artefatti agenti non esistono e vanno compilati (su Windows il setup invoca `build.bat` da sé) |
| `nssm.exe` | **scaricato da `setup.py`** con SHA-256 pinnato: serve per installare gli agenti come servizi Windows |
| `yara64.exe` | **scaricato da `setup.py`** con SHA-256 pinnato: serve per le scansioni YARA sull'endpoint |

I due binari non sono nel repo (`.exe` è in `.gitignore`): li prende il setup e ne verifica l'hash — prima dell'estrazione e sull'eseguibile. Se la rete manca (o l'hash non torna) l'installazione **prosegue** e dichiara cosa resta spento, con il comando per metterli a mano; `--skip-binaries` salta il download.

The `.bat` files are **not** a required step: `aegis.bat` is a convenience menu
for start/stop/logs/build in development. Local AI does not start by default:
`set AEGIS_WITH_AI=1` before `setup.py` to enable ollama.

### Updating (data preserved)

```cmd
python scripts/setup.py update
```

Rebuilds the images and restarts the stack **without touching the database**
(events, alerts, users and agents live in the DB volume; the schema is
self-created at startup). Use `--rebuild-agents` to recompile the host agents
too.

### Alternatives, and optional extras

- Manual path: `aegis.bat` (interactive menu: backend, agents, build, pilot)
  and `docker exec aegis-brain python -m app.admin bootstrap <email> <password>`
  for the first admin.
- **Kernel telemetry (ETW)**, optional: install [MinGW-w64](https://winlibs.com/)
  and the build compiles `aegis-etw.exe`; the launcher wires it to Guard by
  itself. Without it everything still works — Guard declares the degradation
  and falls back to user-mode polling.
- **`nssm.exe`** (installing agents as Windows services) and **`yara64.exe`**
  (on-agent YARA scans) are the only two binaries not shipped in the repo.
  `setup.py` downloads both with a **pinned SHA-256** (checked on the archive
  and again on the extracted executable) and installs them where the
  installers expect them. Offline, or if the hash does not match, nothing is
  installed and the installer tells you the exact manual step — the platform
  still comes up, declaring the missing capability instead of faking it.

### Manual installation (without the script)

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

### Deployment profiles

| Profile | Command | Notes |
|---|---|---|
| Lab (default) | `docker compose up -d --build` | Dev TLS internal, porte localhost |
| Pilot | `docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.mtls.yml up -d --build` | mTLS :8443, richiede `.env` senza placeholder + `BACKUP_PASSPHRASE` |
| Observability (lab) | `docker compose -f docker-compose.yml -f docker-compose.observability.yml --profile observability up -d --build` | Prometheus `localhost:9090` + Grafana `localhost:3001`, richiede `GRAFANA_ADMIN_PASSWORD` |

Equivalent installer scripts: `./install.sh lab|pilot [--observability]` and `.\install.ps1 lab|pilot [-Observability]` (never combined with pilot).

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

- **Dashboard**: Bearer JWT after `POST /api/v1/auth/login` or register. Telemetry, rules, VaultX, OSINT, AI, OCSF export and Aegis Total all require JWT.
- **Roles**: `ROLE_PERMISSIONS` in `app/core/deps.py` maps `viewer`/`user`/`auditor`/`responder`/`analyst`/`admin` to permissions. The role is read from the database on **every** request, so a change applies without re-login. Registration always creates a `user`: privilege is granted from a shell, never from an exposed API.

  ```cmd
  docker exec aegis-brain python -m app.admin list
  docker exec aegis-brain python -m app.admin set-role <email> admin
  ```

  Without at least one `admin`, host isolation, deploy approval, rule and alert deletion and site assignment all return 403 by design. `set-role` refuses to demote the last remaining admin unless `--force` is given.
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
set AEGIS_GATEWAY_URL=http://localhost:8000/api/v1/telemetry/report
set AEGIS_ENROLL_KEY=<key>
jre-new\bin\java.exe -jar target\aegis-guard.jar
```

Due dettagli che fanno fallire l'avvio in modo poco leggibile:

- **Serve una JVM 21+**, e la `java` del `PATH` non è automaticamente adatta: se
  è una 8, il servizio si installa, parte e muore con
  `UnsupportedClassVersionError`. L'installer (`install.ps1`) verifica la
  **versione** e usa il percorso risolto, non la stringa `java`.
- **`AEGIS_ENROLL_KEY` è obbligatoria** anche quando `secret.json` esiste già:
  `Config.ENROLL_KEY` viene letta all'avvio con `getEnvOrThrow`, quindi senza di
  essa il processo termina subito.

Se usi il runtime minimo creato da `build.bat`, deve contenere il modulo
`jdk.net`: Apache HttpClient 5 usa `jdk.net.Sockets` e `jlink` non deduce le
 dipendenze del codice sul classpath. Il modulo è già nell'elenco
`--add-modules` di `build.bat`.

## Telemetry Collection Layers

Ogni sorgente entra nello **stesso** modello evento e nello **stesso** motore di
rilevazione. Due strade convergono, e la prima non richiede alcun agente
residente sul sistema osservato.

| Livello | Dove gira | Cosa porta | Firma richiesta |
|---|---|---|---|
| **eBPF** (`aegis-ebpf/`) | Linux, kernel | `sched_process_exec`, `do_exit`, TCP ESTABLISHED via ringbuf | no (verifier del kernel) |
| **ETW Kernel providers** (`aegis-ebpf/aegis_etw.c`) | Windows, consumer user-mode | `Kernel-Process` 1/2, `Kernel-Network` TcpIp | no (provider di sistema) |
| **Agenti endpoint** | host | Guard (processi, persistenze, servizi), NodeTrace (CPU/RAM/disco/rete/utenti) | enrollment firmato + mTLS |
| **Sorgenti di log** | appliance, server | syslog RFC5424/3164, Windows Event, Zeek, Suricata, nginx/Squid, firewall | nessuna installazione: solo una riga verso l'endpoint |

Su Linux la telemetria kernel è nativa (eBPF, validata 300/300 eventi senza
perdite su kernel 6.6 con BTF). Su Windows lo è tramite ETW: `aegis_etw.c` è un
consumer **user-mode** dei provider di sistema (nessun driver, nessuna firma),
che Guard stesso spawna quando `AEGIS_ETW_ENABLED=true` e legge dal suo stdout
(`EtwPipeSource`). Il servizio gira come LocalSystem, quindi il collector
eredita l'elevazione: zero UAC, zero passaggi manuali. Il build lo compila
automaticamente quando MinGW-w64 è presente, e l'installer/l'avvio lo
deployano e abilitano da soli. Un driver kernel-mode proprietario serve solo
per la **prevenzione inline**: quella richiede firma EV e attestazione
Microsoft, ed è fuori scope insieme a ETW-TI.

**Honest scope.** Windows Event Log, Windows Firewall log e telemetria degli
agenti sono **reali** sull'host di lab. Zeek, Suricata, Squid/nginx e pfSense
sono dimostrati con **sample sintetici in formato reale** (`scripts/siem_demo.py`),
non con traffico di produzione: servono a provare i parser e la pipeline, non a
produrre metriche di detection su traffico reale.

## Features

### Discovery Center
- **Network scan**: ARP + ICMP sweep + TCP connect scan — finds ALL devices on subnet, not just those with open ports
- **MAC vendor lookup**: OUI database identifies device manufacturers (Samsung, Apple, Cisco, etc.)
- **Agent status per IP**: `guard_status` and `nodetrace_status` columns show which agents are deployed/active on each host
- **Signed one-line enrollment**: `POST /api/v1/deploy/token` issues a short-lived token; the generated `install.ps1` / `install.sh` executes a signed one-liner on the target. Credential-based WinRM/SSH deployment was **removed**, not disabled (see `docs/OPERATIONS.md`).
- **Synchronize agent status**: Button to sync DiscoveredHost agent states with live Agent table

### Detection Rules Engine
- **MITRE ATT&CK metadata**: Each static rule carries tactic, technique, and technique ID (T1059, T1134, T1036, etc.)
- **Custom rules**: AND/OR multi-condition rules, whitelist (hostname/IP exclusions), auto-remediation actions
- **Rule testing**: `POST /api/v1/rules/test` to test rules against sample event data

### YARA & FIM (Static Sandboxing + File Integrity Monitoring)
- **YARA rules managed from the dashboard**: create/enable/disable SOC signatures (admin/analyst); scans run on-demand on any endpoint via the official `yara64.exe` (deployed by the installer into `bin/`), every match becomes a HIGH alert and a searchable event
- **YARA in Aegis Total**: uploaded samples are scanned with the active SOC signatures (yara-python); a match raises the score by fact, not heuristics — the report shows the matched rule and strings
- **File Integrity Monitoring in-process**: configure a per-agent watchlist (Run keys, Tasks, services, hosts, cron, systemd...) from the dashboard; Guard (WatchService + SHA256 baseline) reports every change as an OCSF File Activity event with MITRE mapping (T1543/T1547 for persistence paths)
- **Honest limits, declared**: FIM is user-mode telemetry (not a minifilter driver); hashing is capped at 8 MB per file; missing `yara64.exe` degrades scans with an explicit ack, never a silent "looks fine"

### OSINT + AI Automation
- **Auto-enrichment**: When an alert fires, IPs/domains in the alert context are automatically looked up via VirusTotal, Shodan, AbuseIPDB
- **Pluggable AI provider** — chosen **from the dashboard** (Settings → AI Provider), no `.env` edit and no restart: `auto` (default) | `disabled` | `ollama` | `gemini` | `openai`, plus the model per provider (`GET`/`PUT /api/v1/ai/settings`). A value set explicitly in `.env` wins over the dashboard, and the UI labels each field with where its value comes from (`da .env` / `da dashboard` / `default`) so a field that has no effect never looks like it should.
  - `auto` uses **what actually works**: a local Ollama **only if it responds** (short reachability probe), otherwise Gemini/OpenAI if a key exists, otherwise `disabled`. A configured-but-dead endpoint never turns into a stream of connection errors.
  - `disabled` is a first-class state, not a failure: `GET /api/v1/ai/status` returns provider/model/`local`/reason and the dashboard shows it — no fake AI text.
  - **Cloud keys from the dashboard** (Settings → Integrations): `Gemini` and `OpenAI / OpenAI-compatible` appear in the catalog like the OSINT providers, encrypted at rest (KEK), env wins over DB.
  - **Data-exit control** (`AI_AUTOMATIC_ENRICH`, default **off**): with a **cloud** provider, automatic alert enrichment happens only if you switch it on (Settings → AI Provider) — alert context (already anonymized: IPs/emails/tokens redacted) leaves the network only when you ask. With a **local** provider enrichment is always on, because nothing leaves the machine. The flag is in the dashboard and in the `.env`, and the effective value is whatever the resolution returns.
  - **Ollama is optional and not started by default**: the stack runs light (`aegis.bat start`). Enable local AI with `set AEGIS_WITH_AI=1` and pick the model your hardware can run (`set AEGIS_MODEL=qwen2.5:14b`). Point `OLLAMA_URL` at a **powerful machine on your network** to keep AI local while running big models.
  - Detection does **not** depend on AI at any point: rules, Sigma, behavioral tags, correlation, FIM and YARA are deterministic. AI only summarizes.

### Host agents survive reboot
Docker containers come back on their own (`restart: unless-stopped`), but host agents started by hand die with the session. Autostart is a property of the **installation**, not a manual step:
- **Both agents are Windows services (NSSM)** — `AegisGuard` and `AegisNodeTrace` — installed by their installers:
  `aegis-guard\install\windows\install.ps1` and `NodeTrace\install\windows\install.ps1` (elevated shell; auto-start, restart-on-crash, log file). Uninstall with the matching `uninstall.ps1`.
- **`python scripts/setup.py` registers them for you** when it runs elevated; if it is not, it prints the exact commands instead of leaving a silent gap. Use `--no-autostart` to force dev-mode agents only (two instances per endpoint are never started: either services **or** dev processes).
- **No-admin fallback**: `powershell -ExecutionPolicy Bypass -File scripts/install-agents-autostart.ps1` registers Scheduled Tasks “at log on” (user context; elevated Guard actions unavailable). Remove with `-Remove`.
- Logs: `logs\` — `nodetrace.txt`, `guard.txt`, `nodetrace-service.log`.
- **Auto IP reputation**: OSINT results update the IP reputation database automatically
- **Keys from the dashboard (Settings → Integrations)**: providers are discovered dynamically from the backend catalog, keys are stored encrypted at rest and take effect immediately — no restart. An env var set in `.env` **wins** over the DB value, so ops can still pin a key per deployment.
- **Fallback order**: env var → DB (dashboard) → provider skipped with `api_key_not_configured` (never a hard failure)

### Real-time Updates
- **WebSocket overview**: `/api/v1/ws/overview` pushes a counters snapshot every **30s**. It authenticates with the `aegis_token` HttpOnly cookie — bearer tokens are never placed in the URL, since proxies log URLs.
- **Telemetry transport**: agents push events over **HTTPS** (`POST /api/v1/telemetry/report` and `/report/batch`) with an encrypted local spool and bounded retry — **not** over a persistent WebSocket.
- **Smooth charts**: Recharts AreaChart with Brush zoom, disabled animations for real-time data

### Demo Agent Tag
- Demo agents are tagged `is_demo: true`, excluded from main stats by default
- Yellow "DEMO" badge in Endpoints list
- Toggle to show/hide demo agents
- `?include_demo=true` query parameter to include them in API responses

### VaultX (Encrypted Notes)
- AES-256-GCM encrypted notes, decrypted only for authorized roles and audited
- Generic secret storage (runbooks, tokens, recovery codes). Aegis never requests or stores remote-deploy credentials: deployment uses signed one-line enrollment.

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

### Aegis Total (Static Analyzer)
- **No extension is rejected**: PE/.NET, ELF, Mach-O (incl. fat), Office OLE + OOXML (macro VBA, DDE, Excel 4.0, embedded MZ), PDF (/JavaScript, /OpenAction, /Launch, XFA, data after `%%EOF`), ZIP/tar/gzip/bzip2/xz (bounded recursion, zip-bomb caps), APK/JAR/Java class/WASM, RTF, LNK, SQLite/pcap and plain scripts.
- **Every upload gets a real analysis**: files without a dedicated parser still get magic identification, entropy, string extraction and IOC/secret scanning — never a bare “binary, score 10”.
- **Bounded by design**: per-entry size cap, total-uncompressed cap, nesting depth, member count and text-scan windows, so an adversarial archive cannot stall the worker.
- **Retention**: binaries are never stored — only the sha256, findings and IOCs; reports are deletable (GDPR).
- **Discovery**: `GET /api/v1/total/formats` returns the accepted-format catalog used by the UI.

### OCSF Export (SIEM Interoperability)
- **Standard schema**: alerts are exported as OCSF 1.4.0 **Detection Finding** (class 2004) and process telemetry as **Process Activity** (class 1007), with severity, MITRE ATT&CK `attacks[]`, device/process objects and `unmapped.aegis` for Aegis-specific fields.
- **Ingestion-ready**: `GET /api/v1/ocsf/alerts` returns JSON or **NDJSON** (`?download=true`) for batch pipelines (Splunk, Elastic, Sentinel, AWS Security Lake).
- **No custom parser needed**: `POST /api/v1/ocsf/convert` lets an external producer convert an Aegis event to OCSF without database access.

### SIEM — Multi-source Log Ingestion
- **One pipeline for every source**: pushes land on `POST /api/v1/ingest/{source}` and are parsed, normalized and pushed through the *same* detection → alert → SOAR chain used by agents. An alert raised by a log source can trigger a playbook — it is one product, not two.
- **Parser registry with auto-detection**: `syslog` (RFC 3164 + RFC 5424), generic JSON/NDJSON, **Windows Event Log** (`4624/4625/4688/4697/4720/7045/1102`…), **Zeek** (`conn/dns/http/ssl`), **Suricata** `eve.json`, web proxy (nginx/Squid/Apache), firewall (Windows Firewall, pfSense `filterlog`, iptables). `parser: auto` picks one from the payload shape; `GET /api/v1/ingest/catalog` is the single source of truth for the UI.
- **Unified event model**: every source maps to one OCSF-aligned schema (time, severity, host/user, network 5-tuple, process, file, DNS/HTTP) — no per-source consumer.
- **Real syslog listener**: optional UDP **and** TCP listener (`SYSLOG_ENABLED`, default off, bound to `127.0.0.1` unless `SYSLOG_BIND` is explicitly widened) so an rsyslog/firewall can point straight at the brain. Verified end-to-end on real datagrams, with a bounded queue so a syslog storm is counted and dropped rather than accumulated.
- **Sub-second visibility**: `GET /api/v1/ingest/sources` exposes each source's health (last event, unparsed count, last error) — a silent source is visible, not invisible.

### SIEM — Sigma Rule Engine
- **Industry-standard rules**: Sigma YAML is loaded, field-mapped, modifier-expanded (`contains`, `startswith`, `endswith`, `re`, `all`, `base64`, `cidr`…) and compiled into executable internal rules — mapping custom rules to the format the whole industry writes.
- **Fails loud, never half-way**: a rule using an unsupported modifier/feature is **excluded and reported**, not silently executed on a subset of its logic (`GET /api/v1/ingest/detection-coverage` lists every excluded rule and why).
- **Bundled rules**: 14 real detection rules across Windows Event, Linux auth, Zeek DNS, Suricata and proxy/firewall log sources, each mapped to MITRE ATT&CK.

### SIEM — Multi-event Correlation
- **Threshold and sequence** over Redis-backed sliding windows: `N events in T` (brute-force, port sweep, denied burst) and `A then B` (failed logins **then** a success).
- **Same alert path**: a correlation hit produces a normal alert with MITRE mapping, so triage, incidents and SOAR playbooks work unchanged.
- **Explicitly bounded**: each rule caps its window, bucket size and max tracked entities, so correlation cannot be used as a memory amplifier.

### SIEM — Event Store & Search
- **Time-partitioned storage**: normalized events live in a monthly-partitioned table, so retention is a partition `DROP` instead of a mass `DELETE`.
- **Structured search**: `POST /api/v1/search/events` filters on an **allowlist** of fields with `LIKE`-escaped free text — no column name, operator or `ORDER BY` ever reaches the database from the client; `GET /api/v1/search/events` is the shareable-link variant.
- **Dedup + retention**: repeated relays collapse via `event_id` dedup in Redis; expired partitions are purged on the configured schedule.

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
- **Global limiter**: SlowAPI limiter backed by Redis (`RATE_LIMIT_STORAGE_URI`). The client key is derived from `X-Forwarded-For` only when the request comes from a trusted proxy, otherwise it falls back to the socket peer address — a spoofed header cannot reset the budget.
- **Per-endpoint limits**: `/auth/me` at 30 requests/minute; `/auth/login` and `/auth/register` are additionally throttled per account.
- **AI chat**: Per-user rate limit (configurable via `AI_RATE_LIMIT_PER_MIN`).

### CI/CD Pipeline
- **GitHub Actions**: lint (flake8 + ESLint), security audit (bandit + pip-audit), dependency/image scanning (Trivy), SBOM generation, secret scanning, and test stages.
- **Test isolation**: Dedicated `aegis_test` PostgreSQL database for test runs — never touches production data

### Database Backup
- **Automatic dumps**: `pg_dump` compressed backup every 6 hours via cron
- **Retention**: 7-day backup retention with daily rotation
- **Isolated service**: Docker Compose backup service (`aegis-backup`) on `backup` profile with dedicated volume

## API Endpoints

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /api/v1/auth/register` | none (or admin if `ALLOW_OPEN_REGISTRATION=false`) | Create dashboard user (validated, rate-limited) |
| `POST /api/v1/auth/login` | none | Get JWT (rate-limited + per-account throttle) |
| `POST /api/v1/auth/logout` | Bearer JWT | Blacklist token, clear cookie |
| `GET /api/v1/auth/me` | Bearer JWT | Current user profile (rate-limited 30/min) |
| `GET /api/v1/telemetry/stats` | Bearer JWT | Dashboard counters (supports `?include_demo=true`) |
| `GET /api/v1/telemetry/agents` | Bearer JWT | Agent inventory (supports `?include_demo=true`) |
| `GET /api/v1/telemetry/alerts` | Bearer JWT | Alert list with filtering |
| `GET /api/v1/telemetry/alerts/{id}` | Bearer JWT | Alert detail with telemetry, threat reports, remediations |
| `POST /api/v1/telemetry/alerts/resolve-all` | Bearer JWT | Resolve all unresolved alerts |
| `DELETE /api/v1/telemetry/alerts` | Bearer JWT | Delete all alerts |
| `PATCH /api/v1/telemetry/alerts/{id}/resolve` | Bearer JWT (`triage` to resolve, `respond` to kill) | Resolve single alert with optional kill-process |
| `GET /api/v1/telemetry/threat-reports` | Bearer JWT | AI-generated threat analysis reports |
| `GET /api/v1/telemetry/remediations` | Bearer JWT | Auto-remediation action history |
| `GET /api/v1/telemetry/recent` | Bearer JWT | Recent NodeTrace telemetry |
| `GET /api/v1/telemetry/activity` | Bearer JWT | Mixed timeline (telemetry + alerts) |
| `POST /api/v1/telemetry/report` | X-Agent-Id + Bearer | Agent telemetry report (creates alerts) |
| `POST /api/v1/telemetry/heartbeat` | X-Agent-Id + Bearer | Agent heartbeat |
| `GET /api/v1/telemetry/commands` | X-Agent-Id + Bearer | Agent command queue (Redis) |
| `GET /api/v1/rules/` | Bearer JWT | List custom detection rules |
| `POST /api/v1/rules/` | Bearer JWT (operator) | Create custom detection rule (regex safety-checked) |
| `GET /api/v1/rules/static` | Bearer JWT | List static MITRE ATT&CK rules |
| `GET /api/v1/discovery/status` | Bearer JWT | Current scan status |
| `POST /api/v1/discovery/scan` | Bearer JWT | Network scan (CIDR, ports, ARP + ICMP sweep) |
| `GET /api/v1/discovery/hosts` | Bearer JWT | List discovered hosts (vendor, MAC, agent status) |
| `POST /api/v1/discovery/deploy` | Bearer JWT (`deploy`) | Removed (HTTP 410): credential-based deploy. Use `POST /api/v1/deploy/token` |
| `POST /api/v1/deploy/token` | Bearer JWT (`deploy`) | Issue a short-lived enrollment token for signed one-line install |
| `GET /api/v1/total/formats` | Bearer JWT | Accepted file-format catalog for Aegis Total |
| `POST /api/v1/rules/replay/import` | Bearer JWT | Score an external JSONL corpus (benign/suspicious/malformed) with the real engine |
| `GET /api/v1/ocsf/alerts` | Bearer JWT | Alerts as OCSF 1.4.0 Detection Findings (JSON or NDJSON) |
| `POST /api/v1/ocsf/convert` | Bearer JWT | Convert a single Aegis event to OCSF |
| `GET /api/v1/ocsf/schema` | Bearer JWT | OCSF mapping description for integrators |
| `POST /api/v1/discovery/sync-agent-status` | Bearer JWT | Sync agent deployment states |
| `GET /api/v1/osint/ip/{ip}` | Bearer JWT | IP reputation lookup (VT, Shodan, AbuseIPDB) with cache |
| `GET /api/v1/osint/domain/{domain}` | Bearer JWT | Domain reputation lookup with cache |
| `GET /api/v1/ws/overview` | `aegis_token` HttpOnly cookie | WebSocket counters snapshot every 30s (no token in the URL) |
| `POST /api/v1/ai/chat` | Bearer JWT | AI chat with prompt injection detection |
| `GET /api/v1/ai/threads` | Bearer JWT | List AI conversation threads |
| `DELETE /api/v1/ai/threads/{id}` | Bearer JWT | Delete AI thread |
| `GET /api/v1/soar/playbooks` | Bearer JWT | List SOAR playbooks |
| `POST /api/v1/soar/playbooks` | Bearer JWT | Create SOAR playbook |
| `PUT /api/v1/soar/playbooks/{id}` | Bearer JWT | Update SOAR playbook |
| `DELETE /api/v1/soar/playbooks/{id}` | Bearer JWT | Delete SOAR playbook |
| `GET /api/v1/soar/playbook-executions` | Bearer JWT | List all playbook execution history |
| `GET /api/v1/syslog/events` | Bearer JWT | Query syslog events (severity, hostname, app filter) |
| `POST /api/v1/ingest/{source}` | Bearer JWT / API key | Ingest raw log lines or JSON events; parsed + normalized + detected |
| `POST /api/v1/ingest/test` | Bearer JWT | Dry-run a parser on a payload — nothing is stored |
| `GET /api/v1/ingest/catalog` | Bearer JWT | Parser catalog (single source of truth for the UI) |
| `GET /api/v1/ingest/sources` | Bearer JWT | Configured log sources with health (last event, unparsed, last error) |
| `POST /api/v1/ingest/sources` | Bearer JWT (`operator`) | Register a log source |
| `GET /api/v1/ingest/stats` | Bearer JWT | Ingestion stats (EPS, by source/severity) |
| `GET /api/v1/ingest/detection-coverage` | Bearer JWT | Loaded vs. executable Sigma/correlation rules + exclusions |
| `POST /api/v1/search/events` | Bearer JWT | Structured event search (allowlisted fields, escaped text) |
| `GET /api/v1/search/events` | Bearer JWT | Simple event search (shareable URLs) |
| `GET /api/v1/search/fields` | Bearer JWT | Searchable fields with descriptions |
| `GET /api/v1/search/stats` | Bearer JWT | Event statistics over a time window |
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
- Set `DEBUG=false` and `ALLOW_OPEN_REGISTRATION=false` (the brain refuses to
  start otherwise); for enterprise also `ENTERPRISE_STRICT=true` with
  `MTLS_MODE=required` (refused at startup if missing).
- Keep playbook `script` actions disabled (`PLAYBOOK_SCRIPT_ENABLED=false`,
  default) unless enterprise-approved: they execute shell on the server.
- For production, use `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` to avoid exposing Postgres/Redis ports.
- Replace Caddy `tls internal` with proper TLS certificates (Let's Encrypt).
- Store JWTs in a safer browser session model than long-lived `localStorage` tokens.
- Use incremental Alembic migrations for all schema changes (migrations are idempotent).
- Keep `AEGIS_LOG_LEVEL=INFO` or stricter in production.

Use this software only on systems where you have explicit permission.

## Pilot & Enterprise Readiness

Classification: **advanced prototype** (see `docs/os-validation/NOT-RUN.md` for what is actually validated).

```cmd
REM Preflight host (Windows) / sh scripts/os-preflight.sh (Linux)
powershell -ExecutionPolicy Bypass -File scripts/os-preflight.ps1

REM Preflight tool di sviluppo (python/node/java/docker/porte)
python scripts/dev_preflight.py

REM Detection replay on 3 independent splits (training/validation/regression)
python scripts/replay_report.py --all

REM Threshold calibration report (synthetic panel, not fleet baseline)
python scripts/calibrate_thresholds.py

REM API smoke against live stack
python scripts/api_smoke.py [--base http://127.0.0.1:8000]

REM Pilot soak: N synthetic agents for T seconds (dev DB only)
python scripts/pilot_soak.py --agents 10 --duration 300

REM Browser E2E (needs: npm i, playwright chromium, live stack)
cd frontend && npm run e2e

REM Full audit: machine JSON + human report
python scripts/audit_report.py
```

| Item | Path |
|---|---|
| OS validation procedures + status | `docs/os-validation/` |
| HA runbook + overlay | `docs/HA.md`, `docker-compose.ha.yml` |
| Benchmark method + numbers | `docs/BENCHMARK.md` |
| Operations (profiles, secrets, PKI) | `docs/OPERATIONS.md` |

Production profile: `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d`
(requires `BACKUP_PASSPHRASE`; Postgres/Redis not published). HA overlay adds
resource limits and scale-readiness (`--scale aegis-brain=2`).

## References

| Documento | Path |
|-----------|------|
| Operazioni (profili, segreti, PKI) | `docs/OPERATIONS.md` |
| Runbook pilot e HA | `docs/PILOT_RUNBOOK.md`, `docs/HA.md` |
| Validazione OS | `docs/os-validation/` |
| Benchmark e modello minacce | `docs/BENCHMARK.md`, `docs/THREAT_MODEL.md` |
| Setup aegis-brain | `aegis-brain/SETUP.md` |
| Setup frontend | `frontend/README.md` |
