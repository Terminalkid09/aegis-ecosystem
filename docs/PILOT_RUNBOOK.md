# Pilot runbook — Aegis on-premise (≤100 agent, Fase 9)

Verificato su: **Windows 11** (Guard nativo + ETW degradato), **Ubuntu 24.04** (WSL2, eBPF full, BTF ok), **Debian 12** container (eBPF build+test). **Non verificati** (dichiarati): Windows Server 2022/2025, RHEL 9, eBPF su kernel 5.14 senza BTF — richiedono lab dedicato prima di dichiarare compatibilità.
Requisiti: Docker + Compose v2, Python 3.10+, `POSTGRES_PORT=5444` / `REDIS_PORT_EXTERNAL=6388` liberi, `BACKUP_PASSPHRASE` robusta (≥32 char), `AEGIS_TENANT` non impostato per prod.

## 1. Installazione pulita

### Windows 11 (lab)
```powershell
Copy-Item .env.example .env  # valorizza TUTTI i replace-with-*
.\install.ps1 lab
docker compose ps  # brain healthy, caddy healthy
Invoke-WebRequest http://localhost:8000/health/live -UseBasicParsing
# Guard nativo: aegis-guard\install\windows\install.ps1  (richiede Java 21 + NSSM, verifica ACL + hash)
```

### Ubuntu 24.04 / Debian 12 (lab)
```bash
cp .env.example .env
./install.sh lab
docker compose ps
curl -sk http://localhost:8000/health/live
# Guard nativo: sudo aegis-guard/install/linux/install.sh  (systemd, ProtectSystem=full)
# Verifica eBPF: docker run --privileged -v $PWD/aegis-ebpf:/src debian:bookworm-slim bash /src/test-ebpf.sh  # EBPF_TEST_PASS
```

Verifica comune: `GET /health/live` → `{"status":"alive"}`, `GET /audit/logs?exclude_test=true` → `[]` su fresco, `GET /audit/logs?include_test=true` mostra solo is_test=true.

## 2. Pilot (prod overlay + mTLS)

```bash
./install.sh pilot  # richiede .env senza placeholder, fail-fast se manca BACKUP_PASSPHRASE
# Equivalente manuale:
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.mtls.yml up -d --build
```

Il brain rifiuta di partire se `ENTERPRISE_STRICT=true` e `MTLS_MODE != required` (fail-closed).

## 3. Bootstrap PKI (una tantum)

```bash
docker compose exec aegis-brain python -m app.services.pki --dir /app/pki
# Distribuisci AEGIS_MANIFEST_PUBKEY agli agent (env/GPO/Intune)
docker compose exec aegis-brain cat /app/pki/ca.crt > /tmp/ca.crt  # per Caddy :8443
```

Il volume `pki_data` è persistente e incluso nei backup GPG.

## 4. Enrollment + mTLS

```bash
# Crea token (admin)
curl -sk -H "Authorization: Bearer $JWT" -X POST http://localhost:8000/api/v1/deploy/token -d '{"label":"pilot"}'
# Agent: genera chiave locale + CSR (CN=agent_id), POST /enroll/csr → cert
# Verifica:
curl -sk http://localhost:8000/api/v1/enroll/ca.crt
curl -sk -H "Authorization: Bearer $AGENT" -H "X-Agent-Id: $ID" http://localhost:8000/api/v1/telemetry/heartbeat -d '{}'
# Senza cert quando MTLS_MODE=required → 401; con cert valido → 200; CA errata → 401
```

## 5. Rinnovo

Il cert scade in `PKI_DEVICE_TTL_DAYS` (825 gg). L'agent rinnova automaticamente a `RENEW_DAYS=30` dalla scadenza (CSR nuovo, stessa chiave o nuova). Verifica:
```bash
openssl x509 -in device.crt -noout -dates
# Forza rinnovo: rm device.crt && restart agent -> bootstrap
```

## 6. Revoca

```bash
curl -sk -H "Authorization: Bearer $JWT" -X POST http://localhost:8000/api/v1/enroll/agents/$ID/revoke -d '{"reason":"compromised"}'
# Ogni chiamata successiva dell'agent → 401/403, re-enroll → 403 (riammissione solo manuale: DELETE FROM revoked_certs + rm revoked.txt entry + audit)
```

## 7. Aggiornamento / rollback

```bash
curl -sk -H "Authorization: Bearer $JWT" -X POST http://localhost:8000/api/v1/deploy/update-command -d '{"agent_id":"'$ID'","version":"latest"}'
# L'agent verifica HMAC + manifest Ed25519 (obbligatorio in pilot), stage in update.pending/, ack ok/failed, apply al restart
# Rollback: invia di nuovo la versione precedente
```

## 8. Offline / riavvio / disinstallazione

- Offline: agent spool 50 MB, replay ordinato al ritorno
- Riavvio brain: dedup Redis sopravvive (TTL 24h), gap contati in `/telemetry/stats`
- Disinstallazione Windows: `aegis-guard\install\windows\uninstall.ps1` (stop + remove + directory)
- Disinstallazione Linux: `aegis-guard/install/linux/uninstall.sh` (systemctl disable + rm)

## 9. Errore certificato

- `401 con certificato device: possibile REVOCA o scadenza` → verifica `GET /enroll/agents/$ID/certificate-status`
- `401 Invalid client certificate: CN diverso` → header spoofing o mismatch agent_id
- `503 PKI unavailable` → volume `pki_data` illeggibile (fail-closed)

## 10. Backup / restore prima di purge/upgrade

```bash
docker compose --profile backup up -d aegis-backup  # ogni 6h, retention 7gg, GPG MDC, BACKUP_PASSPHRASE obbligatoria in prod
docker compose exec aegis-backup ls -lh /backups
I_CONFIRM_RESTORE=yes ./scripts/restore-db.sh /backups/aegis_db_<ts>.sql.gz.gpg aegis_restore_test
# Tamper: bit flip → GPG MDC rifiuta prima di psql (provato in CI con container usa-e-getta)
I_CONFIRM_RESTORE=yes BACKUP_PASSPHRASE=... ./scripts/restore-pki.sh /backups/aegis_pki_<ts>.tar.gpg /tmp/restore-pki  # PKI
```

## 11. Raccolta metriche 7 giorni (prima di dichiarare pilot stabile)

```bash
# Giornaliero per 7gg: salva stats + top 5 agent + DB size
for d in {1..7}; do
  curl -sk -H "Authorization: Bearer $JWT" http://localhost:8000/api/v1/telemetry/stats | tee stats-$d.json
  curl -sk http://localhost:8000/api/v1/audit/logs?exclude_test=true | jq length
  docker exec aegis-postgres psql -U postgres -d aegis -c "SELECT pg_size_pretty(pg_database_size('aegis'));"
  python scripts/benchmark.py --agents 100 --events 10 | tee bench-$d.log
  sleep 86400
done
# Criteri pilot OK: p99 ingestion <100ms, 0 gap non spiegati, DB growth <20 MB/giorno per 100 host, 0 revoche perse dopo reboot
```

Non passare a 1 000 agent senza aver eseguito `scripts/benchmark.py --agents 1000 --events 10` e aver verificato DB <5 GB e p99 <1s su hardware pilot (2 vCPU/4 GB) e aver testato RHEL/kernel 5.14 in lab dedicato.
