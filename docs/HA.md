# High availability — runbook (audit P4)

## Verified code state (multi-replica safe)

- **Event dedup**: Redis SETNX + in-memory LRU (`event_dedup.py`); two consumers
  do not duplicate alerts.
- **Ingest rate limit**: Redis-first with local fallback (`rate_guard.py`).
- **JWT blacklist / correlation / anomaly**: shared through Redis.
- **SEQ tracker**: per-worker memory; with two consumers, gaps can be counted
  twice (metrics only, never data loss). Accepted and documented.
- **Redis consumer**: `BRPOPLPUSH` + processing + DLQ; killing a worker with
  `-9` requeues at boot, with no loss.
- **Commands**: Brain and Link use atomic claim, processing list, visibility
  timeout, idempotent ack and DLQ. The guarantee is at-least-once: a crash
  between execution and ack can duplicate the action; it is not exactly-once.
  AP-123 is in **Test**, not Done. The Link event path still has a non-atomic
  check+push (AP-122).

## Scaling (same host, available today)

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  -f docker-compose.ha.yml up -d --scale aegis-brain=2 --scale aegis-link=2
```

Caddy balances through DNS round-robin on `aegis-brain`/`aegis-link` (no
Caddyfile change). Verify `GET /health/ready` on both and `docker compose ps`.

## True production (multi-host, still to do)

1. **Managed PostgreSQL with a replica** (RDS/Cloud SQL/on-prem Patroni) plus
   verified encrypted backups (purge already requires them).
2. **Redis Sentinel or Cluster** and `REDIS_URL` on the Brain pointing to the
   VIP.
3. **Brain/Link on 2+ nodes** (Swarm/K8s or Compose on separate hosts) with
   Caddy configured for both upstreams.
4. **Shared backup directory** (`BACKUP_DIR` on a shared volume/S3).
5. **Alerts**: `sendFailed>0`, growing DLQ, `not_ready`, p99 latency.

## Non-HA by decision (documented)

- `aegis-postgres`, `aegis-redis`: single-instance in Compose. They are the only
  SPOFs; the plan above removes them.
- Ollama: optional best-effort (degrades, does not block readiness).
- Agents: one per host by design (anti-double PidLock).
