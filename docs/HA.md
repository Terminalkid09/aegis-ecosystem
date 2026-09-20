# Alta disponibilità — runbook (audit P4)

## Stato verificato del codice (multi-replica safe)
- **Dedup eventi**: Redis SETNX + memoria LRU (`event_dedup.py`) — due consumer
  non doppiano gli alert.
- **Rate limit ingest**: Redis-first con fallback locale (`rate_guard.py`).
- **JWT blacklist / correlation / anomaly**: Redis-condivisi.
- **SEQ tracker**: memoria per-worker — con 2 consumer i gap possono essere
  conteggiati due volte (metriche, mai perdita). Accettato e documentato.
- **Consumer Redis**: `BRPOPLPUSH` + processing + DLQ — kill -9 di un worker =
  requeue al boot, niente perdita.

## Scalare (stesso host, pronto oggi)
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  -f docker-compose.ha.yml up -d --scale aegis-brain=2 --scale aegis-link=2
```
Caddy bilancia via DNS round-robin su `aegis-brain`/`aegis-link` (nessun cambio
Caddyfile). Verificare: `GET /health/ready` su entrambe, `docker compose ps`.

## Produzione vera (multi-host, da fare)
1. **Postgres managed con replica** (RDS/Cloud SQL/on-prem Patroni) + backup
   cifrati verificati (la purge li richiede già).
2. **Redis Sentinel o Cluster** + `REDIS_URL` dei brain verso il VIP.
3. **Brain/link su 2+ nodi** (Swarm/K8s o compose su host separati) + Caddy
   con entrambi gli upstream.
4. **Backup dir condiviso** (`BACKUP_DIR` su volume condiviso/S3).
5. **Allarmi**: `sendFailed>0`, DLQ in crescita, `not_ready`, latenza p99.

## Non-HA per scelta (documentato)
- `aegis-postgres`, `aegis-redis`: single-instance in compose. Sono gli unici
  SPOF: il piano sopra li rimuove.
- Ollama: best-effort opzionale (degrada, non blocca readiness).
- Agenti: uno per host per disegno (PidLock anti-doppio).
