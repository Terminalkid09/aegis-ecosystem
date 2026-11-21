# Aegis — Threat Model (M0)

Version 1.2 — 2026-11-20 — branch `feat/4.3-agent-go`.

Scope frozen by the approved decisions: no Android; Windows and Linux targets;
Windows 11 + Server 2022/2025 primary, Windows 10 lab-only; Ubuntu 22.04/24.04,
Debian 12, RHEL 9; full eBPF where kernel/BTF allow it with an explicit
fallback; on-premise with Docker Compose primary; optional Cloudflare Tunnel
later; Kubernetes after stabilization; one organization per deployment with
sites/subnets/groups; multi-tenant SaaS deferred; allowed data includes command
line, username, path, hash and network destinations; configurable retention:
telemetry 14 days / alerts+incidents 90 days / audit 365 days / syslog 30 days.

Verified against code (not descriptions): `aegis-brain/app/main.py`,
`app/core/{config,deps,security,oidc,secrets}.py`,
`app/api/v1/{router,auth,enroll,deploy}.py`, `app/database/models.py`,
`docker-compose.yml`, `Caddyfile`, `aegis-ebpf/README.md`.

## 1. Assets

| # | Asset | Where it lives | Notes |
|---|---|---|---|
| A1 | Endpoint telemetry / events | PG `telemetry`, Redis queue, `aegis-brain/artifacts` no | Allowed: cmdline, username, path, hash, network destination |
| A2 | Alerts, threat reports, incidents | PG `alerts`, `threat_reports`, `incidents`, `incident_alerts` | 90-day target retention |
| A3 | VaultX credentials | PG `notes` (encrypted, `encrypted_dek` on `users`) | `MASTER_KEY_B64` envelope |
| A4 | Single-use enrollment token | PG `enroll_tokens` (SHA-256 hash only) | Default TTL 15 min, single-use, revocable; a token with `target_hostname` is the only accepted proof for re-enrollment |
| A5 | Agent secrets (device token) | PG `agents.device_token_hash` (Argon2) + `meta.device_token_proof` (SHA-256 bound to the hash), local 60 s cache | Never plaintext; re-enrollment/revocation invalidate the proof; revocation is checked against the DB on every request |
| A6 | Agent artifacts / OTA | `ARTIFACT_DIR` (`/app/artifacts`) | Ed25519 manifest required; HMAC OTA removed in 4.1.0 |
| A7 | Agent commands (including `UPDATE_AGENT`, isolate) | Redis queue through `telemetry_service.send_command_to_agent` | Queue with 202 fallback if Redis is down |
| A8 | Audit log | PG `audit_logs` | 365-day target retention |
| A9 | Syslog | PG `syslog_events`, UDP 1514 through aegis-link | 30-day target retention |
| A10 | Dashboard sessions (JWT) | Redis `bl:{jti}` blacklist | Fail-closed if Redis is down |
| A11 | PostgreSQL backup | `postgres_backups` volume, 6 h cron, `RETENTION_DAYS=7` | Encrypted when `BACKUP_PASSPHRASE` is configured |
| A12 | Server keys (JWT, API, enroll, master) | External env/file only, never in repo | Placeholder validation in `config.py` |

## 2. Actors and roles (verified)

Real DB roles: `viewer`, `user` (legacy alias for viewer), `auditor`,
`responder`, `analyst`, `admin` (`User.role`). `app/core/deps.py` defines the
explicit permission matrix and `require_perm`; `admin` is the only role with
`manage`. Legacy endpoints still use role checks (`_require_deploy_operator`,
incident/playbook RBAC, bulk alerts), but new endpoints use permissions. The
last-active-admin invariant applies to the Users API and to OIDC role sync.

| Actor | Capabilities | Trust |
|---|---|---|
| admin | Everything, including deploy, rules, isolation | Trusted, audited |
| analyst | Triage, incidents, one-liner deployment | Trusted, audited |
| user/viewer | Read own area | Semi-trusted |
| aegis-agent / legacy Guard/NodeTrace | Telemetry, heartbeat, command ack | Untrusted: every call authenticated |
| deploy operator | Creates tokens/jobs, copies the one-liner to the target | Trusted, transient |
| remote approver | Approves through PIN+token in the target GUI | Semi-trusted, rate-limited |
| attacker | Network, compromised endpoint, malware upload (Total) | Untrusted |

## 3. Trust boundaries and flows

```text
endpoint (user-mode, NO driver) --TLS (Caddy; `tls internal` in lab)--> Brain :8000
  | enroll: static key (headless) OR single-use token -> per-agent secret
  | runtime: device secret (Bearer) + heartbeat/version/capabilities
  +-- kernel collector (eBPF/ETW) -> JSON pipe/file -> agent -> POST /telemetry/report[/batch]

browser --HttpOnly cookie `aegis_token` + Bearer--> Brain
  (CSRF origin check on cookie mutations, security headers,
   CORS allowlist, rate limit)

aegis-link/syslog --X-Api-Key / UDP 1514--> Redis --> Brain consumer --> PG
Brain --> external OSINT (VT/Shodan/AbuseIPDB, optional) / local Ollama
deploy: admin/analyst -> short token -> ps1/sh one-liner (TLS transport)
        -> enroll -> OTA Ed25519 (manifest key)
```

Critical boundaries: kernel→user pipe (telemetry only, never commands); Redis
(blacklist/queue: failure = deny, never allow); `ARTIFACT_DIR` (basename only,
no traversal); DB (Alembic migrations `0001..0025`, `CREATE_ALL` only in dev).

## 4. API and authentication inventory (verified by decorator)

| Prefix | Main routes | Auth |
|---|---|---|
| `/auth` | `register, login, logout, me, oidc/*` | Local login/register disabled when OIDC is enabled and `OIDC_ALLOW_LOCAL_LOGIN=false`; JWT+cookie+blacklist; rate limit 5–30/min; CSRF origin check |
| `/enroll` | `POST /enroll`, CSR, revoke, CA | Static key (compare_digest) or single-use token, then device secret |
| `/telemetry` | alerts CRUD+resolve-all, agents, recent, activity, stats, `report`, `report/batch`, heartbeat, commands+ack, remediations, threat reports, process tree, isolate/release | JWT dashboard; device secret per agent |
| `/` compat | `register, update, heartbeat, commands[/batch]` (NodeTrace legacy) | Enroll key / device secret |
| `/deploy` | token create/list/revoke, install.ps1/sh, artifacts, update-command, jobs, request-approval/approve | analyst/admin; install via `X-Enroll-Token`; artifact via agent auth; approve via PIN+token or analyst/admin, rate limit |
| `/soc` | incidents CRUD, attach, auto-group | JWT; writes analyst/admin |
| `/rules` | custom CRUD, static, coverage, test | JWT |
| `/soar` | playbooks CRUD, executions | JWT; `script` admin-only |
| `/discovery` | scan, hosts, reputation, demo, deployment plan, sync-agent-status | JWT; demo denied when `ALLOW_DEMO=false` |
| `/vault` | encrypted notes CRUD | JWT |
| `/osint` | IP/domain/batch/enrich/history | JWT + 24 h cache |
| `/ai` | threads, chat, delete | JWT + rate limit |
| `/syslog` | events | JWT |
| `/audit` | logs | JWT |
| `/total` | disclaimer, reports CRUD, upload | JWT + disclaimer + audit |
| `/ws` | `overview` | JWT through query parameter |
| `/health` | live/ready/startup/circuit-breakers | None (status only, no data) |

## 5. Attack scenarios covered by the model

T1 enrollment-token replay; T2 brute-force enroll/login/approve (rate limit +
short expiry); T3 stolen JWT (fail-closed blacklist, HttpOnly cookie, CSRF origin
check); T4 compromised agent injecting telemetry (per-device auth, schema
validation, never trust IP alone); T5 local queue tampering (counters + defined
offline behavior); T6 altered manifest/artifact (Ed25519, no apply without a
signature); T7 server change through unauthenticated config (signed/pinned
config); T8 agent privilege escalation (least privilege; root helper only where
required); T9 cross-site/organization access (sites as an authorization
boundary); T10 log/query injection (safe logging + parameterized queries); T11
secrets in logs/artifacts (scanning, never plaintext in Redis); T12 queue/DB DoS
(backpressure, target cap, ephemeral worker); T13 stolen backup (encryption);
T14 supply chain (SBOM/signature/provenance).

## 6. Demo / lab / production

`ALLOW_DEMO=false` in production; `agents.is_demo`, `?include_demo` and demo
endpoints are blocked; no destructive automatic response in demo. The dev
Compose stack binds ports to loopback; `docker-compose.prod.yml` hides
PostgreSQL/Redis; `DEBUG=false` enables secret validation; production TLS uses
Let's Encrypt through Caddy when `ACME_EMAIL` is a real address; `tls internal`
is lab-only. `.env` / `secret.json` files are never in the repository (ignored
and untracked).

## 7. Explicit gaps (tracked, not ignored)

- per-device mTLS and PKI: implemented for pilot; native service packaging
  remains outside 4.3;
- sites/subnets/groups and the five-role model: roadmap, not current;
- retention enforcement 14/90/365/30: configuration target, not a guarantee;
- encrypted backup + tested restore: present, but the full disaster-recovery
  drill remains a release gate;
- SBOM/signature/provenance/pinning: partially implemented; 4.3 is checksummed
  and provenance-attested, not cosign-signed;
- signed driver / tamper protection: outside the roadmap; user-mode + OS
  firewall only. A local administrator can stop ETW or the agent, as documented
  in `KERNEL_AND_DRIVERS.md`;
- honeypot exposure: the base compose keeps all deception listeners internal;
  the explicit `docker-compose.kraken-honeypot.yml` overlay is required to
  publish them. SSH/HTTP are the default protocols; FTP/Telnet/SMB/RDP are
  opt-in, and SMB/RDP are banner-grade rather than full protocol servers;
- container limits: CPU/RAM/PID limits and `no-new-privileges` are set, but the
  broker still needs the Docker socket to create sandboxes. It is internal-only,
  non-root and capability-dropped, but it remains a high-privilege component.
