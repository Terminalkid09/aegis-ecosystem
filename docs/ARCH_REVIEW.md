# Review architetturale Aegis — modular monolith (Fase 9)

**Decisione**: mantenere `aegis-brain` come **modular monolith** su FastAPI.
Nessun split in microservizi ora: non c'è un collo di bottiglia misurato che
lo giustifichi per pilot ≤100 agent (vedi `docs/BENCHMARK.md`).

## Misure attuali (pilot 100 host)

- Ingestione: **<10 ev/s** picco, 0.01 ev/s medio → single worker `uvicorn --workers 1` ok.
- DB: **~150 MB** a 90gg (90k telemetry + 4.5k alert) → singolo PG 16-alpine ok.
- Redis: code comandi + dedup + alert suppression (TTL 1h) → singolo Redis 7 ok.
- Detection: replay **5–6k ev/s**, latenza **<0.1 ms** → in-process, no worker separato.
- Correlazione: grouping e beacon in Redis, <1 ms per batch.

## Colli potenziali verso 1 000 host

- PG ingestione: 10k telemetry/giorno → 900k righe a 90gg (~1.5 GB). Oltre
  500 host valutare **partizionamento temporale** (`telemetry` per mese) e
  indici `device_id, timestamp`.
- Redis: coda comandi per 1k host → ~1k chiavi, ancora ok ma monitorare
  `maxmemory` e `queue saturation` (già esposti via `stats()`).
- Detection: 10k ev/s picco → worker async dedicato con coda prioritaria.
- Correlazione: beacon su sorted set per `(agent,pid,remote)` → 1k host
  ok, ma pulizia TTL 1h va monitorata.

## Moduli che *potrebbero* diventare servizi

Solo se le metriche lo richiederanno:

- `telemetry_ingestion` → servizio ingest separato (se PG diventa collo)
- `detection_engine` → worker Python separato (se CPU detection >50% ingestione)
- `correlation/beacon` → servizio Redis+PG dedicato (se memoria Redis >80%)
- `pki/manifest` → sidecar firmatura (se OTA >100/min)

Per ora restano **moduli interni** con interfacce chiare:
`app/services/{replay,event_dedup,incident_grouping,detection_context,pki,mtls,fleet}`.

## Deployment

- **Compose resta principale** (lab e pilot). Prod overlay aggiunge `ENTERPRISE_STRICT`,
  log rotation, `BACKUP_PASSPHRASE` obbligatoria, volumi `pki_data`/`artifact_data`.
- **Kubernetes non implementato ora**: valutato come `helm/` futuro quando
  pilot dimostrerà bisogno di HA (2+ brain, PG HA). Documentazione in
  `docs/OPERATIONS.md` § deploy: lab vs pilot, Cloudflare Tunnel opzionale.

## Rischi se si splitta ora

- Complessità operativa senza beneficio (2× deploy, tracing, secret sync).
- Transazioni distribuite per alert/incident (oggi ACID in PG).
- Overhead rete per detection (oggi in-process, <0.1 ms).

**Verifica**: `scripts/benchmark.py --agents 1000 --events 10` + `pytest`
su PG/Redis reali prima di qualsiasi split.
