# Aegis — Threat Model (M0)

Versione: 1.0 — 2026-09-11 — branch `dev`.
Scope congelato dalle decisioni approvate: niente Android; target Windows e Linux;
Windows 11 + Server 2022/2025 primari, Windows 10 solo lab; Ubuntu 22.04/24.04,
Debian 12, RHEL 9; eBPF completo dove kernel/BTF lo consentono con fallback
esplicito; on-premise con Docker Compose primario; Cloudflare Tunnel opzionale
dopo; Kubernetes dopo la stabilizzazione; singola organizzazione per deployment
con siti/subnet/gruppi; multi-tenant SaaS rimandato; dati consentiti command
line, username, path, hash, destinazioni di rete; retention configurabile
telemetria 14gg / alert+incidenti 90gg / audit 365gg / syslog 30gg.

Verificato sul codice (non su descrizioni): `aegis-brain/app/main.py`,
`app/core/{config,deps,security}.py`, `app/api/v1/{router,auth,enroll,deploy}.py`,
`app/database/models.py`, `docker-compose.yml`, `Caddyfile`, `aegis-ebpf/README.md`.

## 1. Asset

| # | Asset | Dove vive | Note |
|---|---|---|---|
| A1 | Telemetria endpoint / eventi | PG `telemetry`, Redis queue, `aegis-brain/artifacts` no | Dati consentiti: cmdline, username, path, hash, dest rete |
| A2 | Alert, threat report, incidenti | PG `alerts`, `threat_reports`, `incidents`, `incident_alerts` | Retention target 90gg (da implementare Fase 8/9) |
| A3 | Credenziali VaultX | PG `notes` (cifrate, `encrypted_dek` su `users`) | Envelope `MASTER_KEY_B64` |
| A4 | Enroll token monouso | PG `enroll_tokens` (solo hash sha256) | TTL default 15 min, single-use, revocabili |
| A5 | Segreti agent (device token) | PG `agents.device_token_hash` (argon2), Redis `auth:agent:{sha256}` best-effort | Mai plaintext su Redis |
| A6 | Artefatti agent / OTA | `ARTIFACT_DIR` (`/app/artifacts`) | Firma oggi HMAC simmetrica; PKI/mTLS in Fase 7 |
| A7 | Comandi agent (incl. `UPDATE_AGENT`, isolate) | Redis queue via `telemetry_service.send_command_to_agent` | Coda con fallback 202 se Redis giù |
| A8 | Audit log | PG `audit_logs` | Retention target 365gg (da implementare) |
| A9 | Syslog | PG `syslog_events`, UDP 1514 via aegis-link | Retention target 30gg |
| A10 | Sessioni dashboard (JWT) | Redis `bl:{jti}` blacklist | Fail-closed se Redis giù |
| A11 | Backup PG | volume `postgres_backups`, cron 6h, `RETENTION_DAYS=7` | Oggi non cifrato (gap Fase 9) |
| A12 | Chiavi server (JWT, API, enroll, master) | solo env/file esterno, mai in repo | Validazione placeholder in `config.py` |

## 2. Attori e ruoli (verificati)

Ruoli DB reali: `user` (default), `admin`, `analyst` (`User.role`).
Gating reale: `_require_deploy_operator` (deploy), RBAC incidenti/playbook-script,
bulk alerts. I 5 ruoli roadmap (admin, SOC analyst, responder, auditor, viewer)
sono obiettivo Fase 8, non stato attuale.

| Attore | Capacità | Trust |
|---|---|---|
| admin | tutto incl. deploy, regole, isolamento | fidato, auditato |
| analyst | triage, incidenti, deploy one-liner | fidato, auditato |
| user/viewer | lettura propria area | semi-fidato |
| aegis-guard / nodetrace | telemetria, heartbeat, ack comandi | non fidato: ogni chiamata autenticata |
| operatore deploy | crea token/job, copia one-liner sul target | fidato, transitorio |
| approvatore remoto | approva via PIN+token su GUI target | semi-fidato, rate-limited |
| attaccante | rete, endpoint compromesso, malware upload (Total) | non fidato |

## 3. Trust boundary e flussi

```
endpoint (user-mode, NO driver) ──TLS(Caddy, oggi `tls internal` dev)──▶ brain :8000
  │ enroll: static key (headless) OPPURE token monouso → secret per-agent
  │ runtime: device secret (Bearer) + heartbeat/versione/capabilities
  └──collector kernel (eBPF/ETW) → pipe/file JSON → Guard ExternalEventIngester → POST /telemetry/report[/batch]

browser ──cookie httpOnly `aegis_token` + Bearer──▶ brain (CSRF origin-check su mutazioni cookie, security headers, CORS allowlist, rate-limit)
aegis-link/syslog ──X-Api-Key / UDP 1514──▶ Redis ──▶ brain consumer ──▶ PG
brain ──▶ OSINT esterni (VT/Shodan/AbuseIPDB, opzionali) / Ollama locale (profilo `ollama`)
deploy: admin/analyst → token breve → one-liner ps1/sh (trasporto TLS) → enroll → OTA HMAC(AGENT_ENROLL_KEY)
```

Boundary critici: kernel→user pipe (solo telemetria, mai comandi);
Redis (blacklist/queue: guasto = deny, mai allow); `ARTIFACT_DIR` (solo basename,
niente traversal); DB (migrazioni Alembic `0001..0010`, bootstrap `CREATE_ALL`
solo dev).

## 4. Inventario API e autenticazione (verificato da decorator)

| Prefisso | Rotte principali | Auth |
|---|---|---|
| `/auth` | `register, login, logout, me` | nessuna / JWT+cookie+blacklist / rate-limit 5-30/m |
| `/enroll` | `POST /enroll` | static key (compare_digest) o token monouso non riusabile |
| `/telemetry` | alerts CRUD+resolve-all, agents, recent, activity, stats, `report`, `report/batch`, heartbeat, commands+ack, remediations, threat-reports, process-tree, isolate/release | JWT dashboard; device secret per agent |
| `/` compat | `register, update, heartbeat, commands[/batch]` (nodetrace) | enroll key / device secret |
| `/deploy` | token create/list/revoke, install.ps1/sh, artifacts list/get, update-command, jobs CRUD+status, request-approval/approve | analyst/admin; install via `X-Enroll-Token`; artifact via agent auth; approve via PIN+token o analyst/admin, rate-limit |
| `/soc` | incidents CRUD, attach, auto-group | JWT; scritture analyst/admin |
| `/rules` | custom CRUD, static, coverage, test | JWT (audit modifica in Fase 5) |
| `/soar` | playbooks CRUD, executions | JWT; `script` solo admin |
| `/discovery` | scan, hosts, reputation, demo, deployment plan, deploy legacy, sync-agent-status, scan-via-agent | JWT; demo vietata se `ALLOW_DEMO=false` |
| `/vault` | notes CRUD cifrate | JWT |
| `/osint` | ip/domain/batch/enrich/history | JWT + cache 24h |
| `/ai` | threads, chat, delete | JWT + rate-limit |
| `/syslog` | events | JWT |
| `/audit` | logs | JWT |
| `/total` | disclaimer, reports CRUD, upload | JWT + disclaimer + audit |
| `/ws` | `overview` | JWT via query param |
| `/health` | live/ready/startup/circuit-breakers | nessuna (stato, non dati) |

## 5. Scenari d'attacco coperti dal modello

T1 replay token enroll; T2 brute-force enroll/login/approve (rate-limit +
scadenza breve); T3 token JWT rubato (blacklist fail-closed, cookie httpOnly,
CSRF origin-check); T4 agent compromesso che inietta telemetria (auth per-device,
validazione schema Fase 2, mai fidarsi del solo IP); T5 tampering coda locale
(contatori + comportamento offline definito, Fase 2); T6 manifest/artefatto
alterato (HMAC oggi, PKI Fase 7; niente apply senza firma); T7 cambio server via
config non autenticata (config firmata/bloccata, Fase 7); T8 priv-esc agent
(least privilege: helper root solo dove serve, Fase 3/4); T9 cross-site/org
(Fase 8: siti come boundary autorizzativo); T10 injection log/query (logging
sicuro + query parametrizzate, test Fase 10); T11 segreti in log/artefatti
(scan Fase 10, mai plaintext su Redis); T12 DoS coda/DB (backpressure, cap 100
target/job, worker effimero, Fase 2/9); T13 backup rubato (cifratura Fase 9);
T14 supply-chain (SBOM/firma/provenance Fase 10).

## 6. Demo / lab / produzione

`ALLOW_DEMO=false` in prod, flag `agents.is_demo`, `?include_demo`, endpoint
demo bloccati; nessuna risposta distruttiva automatica in demo (SOAR Fase 5/6).
Compose dev espone porte su loopback; `docker-compose.prod.yml` nasconde
PG/Redis; `DEBUG=false` attiva validazione segreti; TLS prod via Let's Encrypt
(su Caddy), mai `tls internal` fuori dal lab. File `.env`/`secret.json` mai in
repo (verificato: ignored, non tracciati — Fase 0).

## 7. Gap espliciti (rinviati alle fasi indicate, non ignorati)

mTLS per-device + PKI (Fase 7, oggi HMAC); siti/subnet/gruppi + 5 ruoli
(Fase 8, oggi 3 ruoli senza siti); enforcement retention 14/90/365/30
(Fase 8/9, oggi solo config); backup cifrato + restore testato (Fase 9);
SBOM/firma/provenance/pin (Fase 10); driver firmato/tamper-protection
(fuori roadmap: solo user-mode + firewall-OS dichiarato in `aegis-ebpf/README`).
