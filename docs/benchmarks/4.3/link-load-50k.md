# Link 50k queue boundary — live evidence

Status: **PASS** for AP-122 on 2026-11-19. This is a controlled-pilot
load test, not a production throughput claim.

## Setup

- `aegis-link` built from the current source (`mvn package -DskipTests`), JDK
  25, run as a container on port 18080;
- dedicated `redis:7-alpine` with no Brain consumer, so the queue cannot drain
  during the measurement;
- overload spool disabled (`AEGIS_LINK_SPOOL_ENABLED=false`), so the only
  valid outcomes are `202` while there is room and `429` at the cap;
- 50,001 HTTP requests, 128 client workers, authenticated with a global API
  key and a fixed agent id;
- each request carries a valid `EventRequest`; the client does not call Redis
  directly.

Command shape:

```bash
python scripts/link_load.py \
  --base http://127.0.0.1:18080 \
  --events 50001 --concurrency 128 \
  --api-key load-key --agent-id load-agent \
  --cap 50000 --expect-cap
```

The dedicated Redis was checked independently with:

```bash
docker exec aegis-link-load-redis redis-cli LLEN aegis:events
```

## Result

| Metric | Value |
|---|---:|
| Requests | 50,001 |
| Concurrency | 128 |
| `202 accepted` | **50,000** |
| `429 rejected` | **1** |
| Redis `LLEN` after the run | **50,000** |
| `5xx` / client exceptions | **0** |
| Throughput | 1,531.6 requests/s |
| p50 | 75.2 ms |
| p95 | 160.1 ms |
| p99 | 215.6 ms |
| Max | 793.5 ms |

The accepted count and Redis depth are exactly the cap; the 50,001st event
received a `429` instead of being accepted or silently dropped. The Lua
`LLEN` + `LPUSH` is the reason the boundary held under concurrent producers.

## What this proves

- the real Link controller, JSON validation, authentication, serialization and
  Redis Lua push work together at the cap;
- a concurrent producer burst cannot make `LLEN` exceed 50,000;
- when the spool is disabled, the overload response is explicit (`429`), not a
  false success.

## Limits

- one Docker Desktop host; no multi-host Redis/Postgres or network partition;
- local HTTP, no Caddy/TLS and no real agent fleet;
- 50,001 requests from 128 client workers, not 50,000 independent agent
  processes;
- spool-enabled overload behavior is covered by the Link unit tests, not by
  this run;
- it does not prove 50k events/s sustained, retention or recovery.

The queue cap is an anti-OOM boundary, not a promise that Redis is durable.
At-least-once delivery and the processing/ack/DLQ path remain separate
evidence in `docs/RELEASE_GATE_4.3.md`.
