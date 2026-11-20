# Pilot runbook — Aegis on-premise (≤100 agents, Phase 9)

Validated on: **Windows 11** (elevated ETW, 95 events), **Ubuntu 24.04 WSL2**
(eBPF full, BTF available) and **Debian 12 container** (eBPF build+test). **Not
validated** (declared): Windows Server 2022/2025, RHEL 9, and eBPF on kernel 5.14
without BTF — these require a dedicated lab before compatibility is claimed.
Requirements: Docker + Compose v2, Python 3.15+, free
`POSTGRES_PORT=5444` / `REDIS_PORT_EXTERNAL=6388`, a strong
`BACKUP_PASSPHRASE` (≥32 characters), and `AEGIS_TENANT` unset for production.

## 1. Clean installation

### Windows 11 (lab)

```powershell
Copy-Item .env.example .env  # fill every replace-with-*
.\install.ps1 lab
docker compose ps  # Brain healthy, Caddy healthy
Invoke-WebRequest http://localhost:8000/health/live -UseBasicParsing
```

### Ubuntu 24.04 / Debian 12 (lab)

```bash
cp .env.example .env
./install.sh lab
docker compose ps
curl -sk http://localhost:8000/health/live
# eBPF check:
docker run --privileged -v $PWD/aegis-ebpf:/src debian:bookworm-slim bash /src/test-ebpf.sh  # EBPF_TEST_PASS
```

Common checks: `GET /health/live` → `{"status":"alive"}`,
`GET /audit/logs?exclude_test=true` → `[]` on a fresh install,
`GET /audit/logs?include_test=true` shows only `is_test=true` records.

### Enrollment token end-to-end

In **Deployment Manager**, create an **AegisAgent (unified)** token. The token is
short-lived and single-use. On Windows, the generated command requires elevated
PowerShell and creates an automatic service with restart-on-crash. On Linux, it
requires root and creates a systemd unit with `systemctl enable --now`; both
paths fail explicitly when the runtime is missing.

The remote dashboard checkbox configures the Brain URL. The local endpoint
dashboard is not a distributable artifact: the backend rejects that choice
instead of producing a partial installation.

## 2. Pilot (prod overlay + mTLS)

```bash
./install.sh pilot  # requires .env without placeholders, fail-fast if BACKUP_PASSPHRASE is missing
# Manual equivalent:
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.mtls.yml up -d --build
```

The Brain refuses to start when `ENTERPRISE_STRICT=true` and `MTLS_MODE !=
required` (fail-closed).

## 3. PKI bootstrap (one-time)

```bash
docker compose exec aegis-brain python -m app.services.pki --dir /app/pki
# Distribute AEGIS_MANIFEST_PUBKEY to agents (env/GPO/Intune)
docker compose exec aegis-brain cat /app/pki/ca.crt > /tmp/ca.crt  # for Caddy :8443
```

The `pki_data` volume is persistent and included in GPG backups.

## 4. Enrollment + mTLS

```bash
# Create a token (admin)
curl -sk -H "Authorization: Bearer $JWT" -X POST http://localhost:8000/api/v1/deploy/token -d '{"label":"pilot"}'
# Agent: generate a local key + CSR (CN=agent_id), POST /enroll/csr → certificate
# Verify:
curl -sk http://localhost:8000/api/v1/enroll/ca.crt
curl -sk -H "Authorization: Bearer $AGENT" -H "X-Agent-Id: $ID" http://localhost:8000/api/v1/telemetry/heartbeat -d '{}'
# Without a certificate when MTLS_MODE=required → 401; valid cert → 200; wrong CA → 401
```

## 5. Renewal

The certificate expires after `PKI_DEVICE_TTL_DAYS` (825 days). The agent renews
automatically at `RENEW_DAYS=30` before expiry (new CSR, same or new key).
Verify:

```bash
openssl x509 -in device.crt -noout -dates
# Force renewal: rm device.crt && restart agent -> bootstrap
```

## 6. Revocation

```bash
curl -sk -H "Authorization: Bearer $JWT" -X POST http://localhost:8000/api/v1/enroll/agents/$ID/revoke -d '{"reason":"compromised"}'
# Every later agent call → 401/403; re-enroll → 403 (manual re-admission only:
# DELETE FROM revoked_certs + rm revoked.txt entry + audit)
```

## 7. Update / rollback

```bash
curl -sk -H "Authorization: Bearer $JWT" -X POST http://localhost:8000/api/v1/deploy/update-command -d '{"agent_id":"'$ID'","version":"latest"}'
# The agent verifies HMAC + Ed25519 manifest (required in pilot), stages in
# update.pending/, acks ok/failed, and applies on restart.
# Rollback: send the previous version again.
```

## 8. Offline / restart / uninstall

- Offline: 50 MB agent spool, ordered replay when connectivity returns.
- Brain restart: Redis dedup survives (24 h TTL), gaps are counted in
  `/telemetry/stats`.
- Windows uninstall: `aegis-guard\install\windows\uninstall.ps1` (stop + remove +
  directory). Legacy Guard is not part of the 4.3 bundle; use the 4.3 agent
  uninstall path for the unified service.
- Linux uninstall: `aegis-guard/install/linux/uninstall.sh` (systemctl disable +
  remove). Legacy Guard is not part of the 4.3 bundle; use the 4.3 agent
  uninstall path for `aegis-unified.service`.

## 9. Certificate errors

- `401 with device certificate: possible REVOCATION or expiry` → check
  `GET /enroll/agents/$ID/certificate-status`.
- `401 Invalid client certificate: CN mismatch` → header spoofing or agent_id
  mismatch.
- `503 PKI unavailable` → `pki_data` unreadable (fail-closed).

## 10. Backup / restore before purge/upgrade

```bash
docker compose --profile backup up -d aegis-backup  # every 6 h, 7-day retention, GPG MDC, BACKUP_PASSPHRASE required in prod
docker compose exec aegis-backup ls -lh /backups
I_CONFIRM_RESTORE=yes ./scripts/restore-db.sh /backups/aegis_db_<ts>.sql.gz.gpg aegis_restore_test
# Tamper: a bit flip makes GPG MDC reject the file before psql (tested in CI with a disposable container)
I_CONFIRM_RESTORE=yes BACKUP_PASSPHRASE=... ./scripts/restore-pki.sh /backups/aegis_pki_<ts>.tar.gpg /tmp/restore-pki  # PKI
```

## 11. Seven-day metric collection (before declaring the pilot stable)

```bash
# Daily for 7 days: save stats + top 5 agents + DB size
for d in {1..7}; do
  curl -sk -H "Authorization: Bearer $JWT" http://localhost:8000/api/v1/telemetry/stats | tee stats-$d.json
  curl -sk http://localhost:8000/api/v1/audit/logs?exclude_test=true | jq length
  docker exec aegis-postgres psql -U postgres -d aegis -c "SELECT pg_size_pretty(pg_database_size('aegis'));"
  python scripts/benchmark.py --agents 100 --events 10 | tee bench-$d.log
  sleep 86400
done
# Pilot acceptance: p99 ingestion <100 ms, 0 unexplained gaps, DB growth <20 MB/day per 100 hosts, 0 lost revocations after reboot
```

Do not move to 1,000 agents before running `scripts/benchmark.py --agents 1000
--events 10`, verifying DB <5 GB and p99 <1 s on pilot hardware (2 vCPU/4 GB),
and testing RHEL/kernel 5.14 in a dedicated lab.
