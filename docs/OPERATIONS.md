# Aegis — On-premise operations (M8 Phase 9)

Operator runbook: clean install, backup/restore, upgrade/rollback, PKI bootstrap
and retention. Commands use Docker Compose (the `backup` profile starts the
backup service). Never put secrets in the repository: use secret files, Vault or
the orchestrator (see `docs/SECRETS.md`); a local `.env` is for the lab only.

For incidents, use the dedicated runbooks in [`runbooks/`](runbooks/): compromised
agent, compromised Brain, compromised Kraken, malware escape, backup and restore.
They are part of the release gate, not appendices. The executable soak, DR, HA,
AP-126/127 and self-improvement gates are documented in
[PRODUCTION_VALIDATION.md](PRODUCTION_VALIDATION.md).

## 1. Clean install

```bash
cp .env.example .env   # fill every replace-with-* value
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose ps                    # all services healthy
curl -sk https://aegis.local/api/v1/health  # {"status":"ok"}
```

Prerequisites: Docker + Compose v2, Python 3.15+ for
`scripts/run_integration_tests.py`, and `POSTGRES_PORT`/`REDIS_PORT_EXTERNAL`
reachable on 127.0.0.1. See `scripts/run_integration_tests.py --help` and
`aegis-brain/tests/conftest.py` (`TEST_DATABASE_URL`/`REQUIRE_INTEGRATION=1` for
CI fail-closed mode).

Checks: `GET /health/live|ready|startup` on the Brain. For a real deployment set
`AEGIS_DOMAIN=<public-fqdn>` and `ACME_EMAIL=<real-address>` in `.env`, keep
`ALLOWED_ORIGINS` and `PUBLIC_BASE_URL` on the same host, point DNS at this host
and allow ports 80/443: Caddy obtains and renews a Let's Encrypt certificate.
The `aegis.local` default uses Caddy's internal CA and is lab-only. With the
Kraken profile, `docker compose ps` must show
`aegis-kraken-sensors` as `healthy`: its healthcheck uses a local
`127.0.0.1:8000` listener, not the honeypot ports, so it cannot create fake
attack events.

## 1a. Docker resource limits

Long-running services accept environment overrides with safe defaults in
`docker-compose.yml`:

```bash
AEGIS_BRAIN_MEM_LIMIT=750m
AEGIS_BRAIN_CPUS=0.75
AEGIS_BRAIN_PIDS=300          # Linux only
AEGIS_KRAKEN_SENSORS_MEM_LIMIT=384m
AEGIS_KRAKEN_SENSORS_CPUS=0.40
AEGIS_KRAKEN_RDP_MEM_LIMIT=896m
```

`scripts/check_compose_limits.py` verifies that the overrides reach the rendered
Compose model without starting a container. For a live load test, start the
stack, then run `scripts/load_limits.sh`: it wraps the existing
`scripts/pilot_soak.py` and captures `docker stats` before/after. `mem_limit` and
`cpus` are Compose v2 fields, not Swarm `deploy.resources`; `pids_limit` is
Linux-only. Size the Brain/Postgres pair together: lowering only the Brain limit
moves pressure to the DB and does not increase throughput.

## 1b. First administrator (localhost and remote)

Self-service registration is disabled by default. There is no implicit admin on
`localhost`: the role is granted from the host shell, never from an HTTP request.
After the first start:

```bash
docker exec aegis-brain python -m app.admin list
docker exec aegis-brain python -m app.admin bootstrap admin@aegis.local '<strong-password>'
```

`bootstrap` creates the account if it does not exist and promotes it to admin;
if it already exists, it verifies the password and does not reset it. For a new
admin, use `create-user <username> <email> <password> --role admin`; to promote
an account whose password is known, use `set-role <email> admin`. Without at
least one admin, host isolation, deploy approval, rule/alert deletion and site
assignment return 403 by design.

Automatic bootstrap (`scripts/setup.py`) prints the password once and does not
store it in `.env`. For automated installation, use
`AEGIS_ADMIN_PASSWORD_FILE` (see `docs/SECRETS.md`). The **Users & Roles** page,
visible only to admins, manages account creation, roles, activation and password
reset with audit records.

## 1b. Enrollment token and host services

In **Deployment Manager**, create a token for **AegisAgent (unified)** and choose
its capability mode: **full** (sensor + endpoint), **sensor only** or
**endpoint only**. There is still one agent, one binary, one identity and one
enrollment; the mode only controls which collectors start. The token is
short-lived and single-use. There are no separate Guard, NodeTrace or "both"
tokens, and there is no SSH/WinRM executor.

To **re-enroll** an already registered host, create the token with
`target_hostname` equal to the existing hostname. The static `AGENT_ENROLL_KEY`
is only for the first enrollment: it cannot replace the device secret of an
existing host. Agents also send the machine-id (`MachineGuid` on Windows,
`/etc/machine-id` on Linux); the Brain stores only its hash and records an
identity change in the audit log.

The generated command:

- requires the target to reach the Aegis URL: it downloads
  `unified-latest.zip` (Windows) or `unified-latest.tar.gz` (Linux) from the
  Brain using the bootstrap token;
- configures the Brain URL, the manifest public key, `AEGIS_AGENT_MODE` and a
  `0600` token file;
- registers `AegisAgent` as a Windows service or `aegis-unified.service` on
  Linux;
- enables automatic start, restart after a crash and verifies the service state
  before exiting successfully.

The 4.3 Deployment Manager always selects the remote dashboard. The API can
still stage files without registering a service, but that is **not** a
deployment: an agent that cannot reach Aegis cannot enroll, heartbeat or receive
commands. The installer states this explicitly.

**Publish artifacts before using the installers.** The one-liner downloads from
`/deploy/bootstrap-artifacts/unified-latest.zip` (or `.tar.gz`), so the file must
exist in `ARTIFACT_DIR`. The 4.3 bundle already publishes it; for a source build,
compile the Go binary and its kernel helpers and pass them to
`scripts/release-bundle.py --agent-dir <dir> --require-agent`.

The Windows archive contains `aegis-agent.exe` and `aegis-etw.exe`; the Linux
archive contains `aegis-agent`, `aegis-collector` and `aegis_exec.bpf.o`. The
target needs **administrator** rights for service registration and the ETW
session; on Linux, eBPF requires `libbpf1` and `CAP_BPF` + `CAP_PERFMON` (or
root). If a helper is missing, the agent reports `quality=degraded:...` and uses
the fallback; it does not pretend the kernel stream is active.

The local dashboard on the endpoint is not distributed: do not select it as an
operational requirement. For isolated companies, use a central dashboard
reachable from the internal network; a local dashboard requires a static bundle,
a local server and authenticated API configuration.

## 2. PKI bootstrap (once, before agents)

```bash
docker compose exec aegis-brain python -m app.services.pki --dir /app/pki
# -> CA in /app/pki/ca.crt + manifest key; distribute the printed pubkey_b64
#    as AEGIS_MANIFEST_PUBKEY to agents (env/GPO/Intune).
```

The one-liner installer injects the manifest public key into the agent
environment; the enrollment token is written to a `0600` file, not to the
persistent environment. OTA is Ed25519-only: a command without a signed manifest
is rejected, with no HMAC fallback.

Recommended: mount `/app/pki` on separate persistent storage and include it in
encrypted backups (without the CA, new signatures are impossible).

### 2b. Agent mTLS rollout (pilot)

1. `python -m app.services.pki --dir /app/pki` (CA + manifest key).
2. Agent: existing enrollment, then the agent generates the key locally and
   calls `POST /enroll/csr` (authenticated with the device secret) → device
   certificate (CN=agent_id). Revocation: `POST /enroll/agents/{id}/revoke`.
3. Validate the terminator: `caddy validate` with `Caddyfile.mtls` (listener
   :8443 `require_and_verify` against `/etc/caddy/pki/ca.crt` mounted from
   `pki_data`), then replace the Caddyfile and restart.
4. Set `MTLS_MODE=required` on the Brain and restart: without a valid certificate,
   agent endpoints return 401; with unreadable PKI, 503 (fail-closed, never
   allow).
5. Rollback: `MTLS_MODE=optional` (verify only when a certificate is present).

## 3. Backup and restore

Automatic backup every 6 hours (`backup` profile), 7-day retention, encrypted
when `BACKUP_PASSPHRASE` is set (otherwise plaintext with an explicit warning):

```bash
docker compose --profile backup up -d aegis-backup
docker compose exec aegis-backup ls -la /backups
```

Manual restore (double confirmation):

```bash
I_CONFIRM_RESTORE=yes ./scripts/restore-db.sh /backups/aegis_db_<ts>.sql.gz.enc aegis
# different target for tests: ... restore-db.sh <file> aegis_restore_test
```

Automated round-trip (creates a disposable database, never touches the real one):

```bash
DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=postgres PGPASSWORD=... \
  BACKUP_PASSPHRASE=... bash scripts/test-restore.sh
```

The GitHub job `Backup Restore Check` runs the same path nightly with an
encrypted backup; `restore-db.sh` uses `ON_ERROR_STOP=1`, so a corrupt dump
cannot finish with exit 0.

PKI restore: copy `/app/pki` back from the backup before signing again.

## 4. Upgrade and rollback

Backend: `docker compose pull/build && up -d` (Alembic `upgrade head` at start;
failure means the container does not start, never a partial schema). Rollback:
`git checkout <previous-tag> && up -d --build` (schema downgrade only with a
dedicated, approved Alembic revision).

Agent: `POST /deploy/update-command {agent_id, version}` (HMAC-signed artifact +
Ed25519 manifest when the public key is distributed). The agent stages and
applies on restart; the ok/failed ack is visible to the SOC. Agent rollback:
re-send `update-command` with the previous version (versioned artifacts in
`ARTIFACT_DIR`, never overwritten).

## 5. Retention purge (manual, destructive)

Approved defaults: telemetry 14 days, alerts 90, audit 365, syslog 30.

```bash
./scripts/purge-retention.sh              # DRY_RUN: counts only
DRY_RUN=0 I_CONFIRM_PURGE=yes ./scripts/purge-retention.sh
```

Run only **after a verified backup**. The alert→(remediation, threat, incident,
playbook) foreign keys are CASCADE/SET NULL: the purge does not orphan rows.

## 6. Daily health

- `GET /telemetry/stats`: `active/stale/offline/isolated_agents`,
  `events_duplicated`, `events_seq_gaps` (measured loss).
- `GET /telemetry/agents?site=<site>`: coverage by site.
- Container logs: 5×10 MB rotation (prod overlay).
- `GET /health/live`: `database`, `redis`, `ollama`, `pipeline`, `pki` and `mtls`.
  `ollama` is optional: if unconfigured or offline it appears as `degraded` but
  does not make the core platform unready. Database, Redis, pipeline, PKI and
  mTLS remain critical dependencies. Use `/health/ready` to decide whether to
  accept traffic and always read the detail of each check.

## 7. Observability (lab "observability" profile)

- Start: `./install.sh lab --observability` (or `.\install.ps1 lab -Observability`).
  Requires `GRAFANA_ADMIN_PASSWORD` in `.env`. The scrape config is tracked at
  `infra/prometheus/prometheus.yml` and mounted read-only. This is an optional
  lab profile, not production monitoring: one Prometheus, 14-day local
  retention, no Alertmanager, no HA and no remote write. Prometheus and Grafana
  bind to `127.0.0.1` only.
- Consoles: Prometheus `http://localhost:9090` (scrapes
  `aegis-brain:8000/metrics` and `aegis-link:8080/actuator/prometheus`), Grafana
  `http://localhost:3001` (login `admin` + `GRAFANA_ADMIN_PASSWORD`).
- Brain metrics: `aegis_http_requests_total`, `aegis_http_request_seconds`
  (histogram), `aegis_events_*` (received/duplicates/errors per agent),
  `aegis_ingestion_latency_*`, detection latency and RedisConsumer queue depth.
- **Not included in pilot**: Prometheus/Grafana are off in pilot; metrics are
  collected through `scripts/benchmark.py` and the Brain `/metrics` endpoint
  (no export).

## 8. Move to non-root runtime (v4.x)

Aegis Brain images run as user `aegis` (non-root, `USER aegis` in the Dockerfile).
If upgrading from a version with root-owned `pki_data`/`artifact_data` volumes,
run once:

```bash
docker run --rm -u 0 \
  -v aegis-ecosystem_pki_data:/app/pki \
  -v aegis-ecosystem_artifact_data:/app/artifacts \
  --entrypoint sh aegis-ecosystem-aegis-brain:latest \
  -c "chown -R aegis:aegis /app/pki /app/artifacts && chmod 700 /app/pki"
```

New installations need nothing: `USER aegis` and the directories created in the
image mean named volumes are already owned by aegis.

## 9. Security and supply-chain notes

- Debian slim base images with HIGH/CRITICAL CVEs that have no upstream fix are
  excluded through `.trivyignore` (each ID is justified; remove it as soon as
  Debian ships the fix). Everything else remains fail-closed (exit code 1).
- `apt-get upgrade`/`apk upgrade` run at Dockerfile build time.
- Maven dependency-check in CI requires `NVD_API_KEY` (fail-closed when absent).

## 10. Signed YARA signature feeds

Feeds are disabled by default. To enable them, set `YARA_FEED_ENABLED=true`,
`YARA_FEED_URLS` (HTTPS), `YARA_FEED_PUBLIC_KEY_B64` and `YARA_FEED_KEY_ID` in
`.env` or the secret store. The Brain verifies the detached Ed25519 signature
over the raw bundle before importing anything; a missing key, bad signature or
oversized bundle leaves the last good rules in place and the sync fails closed.
The publisher private key must never be placed on the Brain host.

```bash
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://aegis.local/api/v1/yara/feeds/status
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  https://aegis.local/api/v1/yara/feeds/sync
```

The UI shows feed state and rule provenance under YARA. Feed rules are marked
`managed` and cannot overwrite a local rule with the same name; removing a rule
from a later bundle deactivates it rather than deleting an operator's history.
Limits: 5,000 rules, 64 KiB per rule and an 8 MiB bundle by default. See
[YARA_FEEDS.md](YARA_FEEDS.md) for the bundle schema and key rotation.

## 11. Caddy in production

Caddy is suitable as the public TLS/reverse-proxy edge when `AEGIS_DOMAIN` is a
real FQDN, `ACME_EMAIL` is monitored, ports 80/443 are reachable and the mTLS
overlay is used for the agent API. It terminates TLS, applies the security
headers and proxies to the frontend/Brain; it is not an HA controller, a WAF or
a monitoring stack. Use multiple replicas behind an external load balancer for
HA, back up `caddy_data`/`caddy_config`, and alert on certificate expiry,
upstream health and 5xx rates. Validate a changed Caddyfile before reload:

```bash
docker run --rm -e AEGIS_DOMAIN=aegis.example.com -e ACME_EMAIL=ops@example.com \
  -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy:2-alpine caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
```

## 12. Secret hygiene in a pilot workspace

`.env`, `.env.bak-*`, `secret.json`, `token.json`, `device.key` and similar
files are excluded from Git, but they are still live secrets on disk. Before
handing a pilot workspace to another operator or archiving it:

1. rotate `JWT_SECRET`, `AEGIS_API_KEY`, `AGENT_ENROLL_KEY`, `MASTER_KEY_B64`,
   database/Redis passwords and any OIDC client secret;
2. revoke enrolled agents and delete `secret.json`/`token.json`/device keys
   that are no longer needed;
3. remove `.env.bak-*` copies and any exported `docker inspect` output;
4. verify that the replacement `.env` is mode `0600` and that backups are
   encrypted with `BACKUP_PASSPHRASE`.

Never place the YARA feed private key, the manifest private key or a backup
passphrase in the Brain container or in a release bundle.
