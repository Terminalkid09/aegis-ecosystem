# Benchmark Aegis (Fase 6)

Misure su host di sviluppo (Windows 11, Python 3.10, i7, 16 GB) del 2026-09-12.
Tutti i numeri sono **CPU-bound deterministici** (replay, dedup) quindi
ripetibili; le misure su DB/rete richiedono stack Docker reale e sono
indicate come stime.

## Replay engine (senza DB)

- 1 000 eventi sintetici (5% sospetti): **~5–6k ev/s**, latenza singola **<0.1 ms**
- Corpus training 12+12: precision/recall/F1 **1.0**, **0 FP/host/day** su
  **1 host-day sintetico**.
- Corpus validation indipendente 16+9: precision/recall/F1 **1.0**, **0 FP/host/day**.
- Corpus regression 7+6: precision/recall/F1 **1.0**, **0 FP/host/day**.
- Gli split validation/regression sono sintetici e non sostituiscono dati reali:
  non è corretto generalizzare questi valori a un ambiente enterprise.
- MTTD non misurabile in replay (solo live).

## Throughput per agent e profili

| Profilo | ev/host/giorno | % sospetti | Esempio |
|---------|----------------|------------|---------|
| light   | 5   | 2%  | ufficio, polling 60s |
| normale | 10  | 5%  | dev, 30s |
| intenso | 50  | 10% | build server, storm exec |

Misura `scripts/benchmark.py`: **per-agent** ~500 ev/s in replay, in produzione
il limite è la rete/DB, non la CPU.

| Scenario | ev/s/agent | CPU agent | RAM agent | Traffico | Latenza ingestione | Latenza detection |
|----------|------------|-----------|-----------|----------|--------------------|-------------------|
| 10 agent, 100 ev | 0.5k ev/s | <2% | ~80 MB | 15 KB/s | 2–5 ms (EventSchema) | <0.1 ms |
| 100 agent, 100 ev| 0.5k | <5% | ~120 MB | 150 KB/s| 2–5 ms | <0.1 ms |
| 1 000 agent, 10 ev|0.4k | <10%*| ~300 MB*| 1.5 MB/s*| 2–5 ms | <0.1 ms |

*1 000 simulati in un solo processo Python: CPU/RAM/traffico estrapolati, non misurati su 1k VM reali (limite hardware: 10 processi paralleli testati, 1k richiede orchestratore).

## Throughput e scaling (stima pilot 90gg, ipotesi esplicite)

**Ipotesi:** evento raw JSON 1.2 KB, indice + TOAST + WAL + metadati 0.8 KB → **2.0 KB/tel**;
alert raw 0.5 KB + indice 0.5 KB → **1.0 KB/alert**. Misura reale su `pg_total_relation_size`
dopo 10k righe pilota conferma ~1.9–2.1 KB/tel.

| Pilot | Profilo | Eventi | Raw | Indici | Alert | **Totale** | Throughput medio |
|-------|---------|--------|-----|--------|-------|------------|------------------|
| 10 host  | normale | 9k  | 11 MB | 7 MB | 0 MB | **~18 MB** | 0.001 ev/s |
| 100 host | normale | 90k | 108 MB | 72 MB | 5 MB | **~185 MB** | 0.01 ev/s |
| 1 000 host| intenso| 4.5M | 5400 MB | 3600 MB | 225 MB | **~9 GB** | 0.5 ev/s |

90k×1.2 KB = **108 MB raw** (non 108 KB). Con indici si raddoppia: il precedente
`~150 MB` per 100 host era sottostimato del 20%; il nuovo `~185 MB` include overhead PG.

Picchi misurati: **<10 ev/s** anche con storm exec (bench eBPF 300 exec in 246 ms).
Conclusione: **singolo worker `uvicorn --workers 1` e singolo PG ok fino a ~300 host normali**;
oltre servono worker async + partizionamento PG (ARCH_REVIEW).

## Overhead sensore

- eBPF: **+15% wall-clock** su micro-benchmark worst-case (`/bin/true` x300,
  ~0.1 ms/exec, 0 persi, 30 ms CPU totali). Su carico reale trascurabile.
- Guard user-mode: scan 1 s, hash solo nuovi, netstat ≤5 s, spool 50 MB bound.
- NodeTrace pooling: 10 s heartbeat, batch 25/2 s, dedup 5 s.

## Coda e resilienza

- Spool cifrato 50 MB, replay ordinato, bound 2000 in RAM (drop-oldest contato).
- Backpressure visibile via `stats()` / `/telemetry/stats` (gaps, dup).
- Retry con jitter, dedup `event_id` (LRU 20k), gap detection per `(agent,boot,seq)`.
- Reconnect testato in e2e (MTLS required, revoca, CA errata, rinnovo).

## Limiti

- Corpus piccolo: **non dichiarare 0 FP globali**, solo su dataset documentato.
- DB growth: stima, non misura su 90gg reali.
- MTTD/triage: solo live (pilot).
- eBPF validato su 6.6 WSL2 + Debian bookworm (BTF ok); kernel senza BTF = partial/fallback.

## Comandi

```bash
python scripts/benchmark.py --quick
python scripts/benchmark.py --quick --json   # + metadati (python/OS/CPU/RAM/commit/seed) e p50/p95/p99
python scripts/benchmark.py --agents 100 --events 100
python scripts/generate_corpus_splits.py --dry-run
python scripts/replay_report.py --all --json
python scripts/audit_report.py --skip-slow
python aegis-ebpf/bench.sh            # overhead eBPF worst-case
python aegis-ebpf/check-contract.py   # compat v1/v2
pytest aegis-brain/tests/test_benchmark.py -v
```
