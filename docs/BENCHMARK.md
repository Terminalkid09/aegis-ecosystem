# Aegis benchmarks (Phase 6)

The CPU-bound measurements (replay, dedup) are from 2026-09-12 on Windows 11,
Python 3.10, i7, 16 GB. The HTTP measurements are from 2026-11-18 on the same
development host with 8 CPUs and Python 3.15. The **5–6k ev/s** in the replay
section is the in-process engine; it is not the throughput of an HTTP endpoint
with PostgreSQL commits. The "Real HTTP ingestion" section below is the relevant
measurement for that path.

## Replay engine (no database)

- 1,000 synthetic events (5% suspicious): **~5–6k ev/s**, single-event latency
  **<0.1 ms**;
- 12+12 training corpus: precision/recall/F1 **1.0**, **0 FP/host/day** on
  **1 synthetic host-day**;
- independent 16+9 validation corpus: precision/recall/F1 **1.0**, **0 FP/host/day**;
- 7+6 regression corpus: precision/recall/F1 **1.0**, **0 FP/host/day**;
- the validation/regression splits are synthetic and do not replace real data;
  these values must not be generalized to a large production environment;
- MTTD cannot be measured in replay; it requires live traffic.

## Real HTTP ingestion — 4.2 (2026-11-18)

Local Compose stack, Brain with **2 uvicorn workers** (Compose default),
PostgreSQL 16-alpine, Redis 7, HTTP client with 30 connections. Every request is
authenticated; the "unique and durable" path uses distinct `event_id` values and
waits for the commit. The Caddy measurement uses TLS and the name `aegis.local`.

| Path | Throughput | Result |
|---|---|---|
| `/telemetry/report`, unique and durable, direct | **247.76 rps** | 2 workers, 3,000/3,000 `200`; 3,008 DB rows; p50 108.7 ms, p95 194.4 ms, p99 279.0 ms |
| `/telemetry/report`, unique and durable, Caddy/TLS | **289.35 rps** | 2 workers, 1,500/1,500 `200`; p50 99.1 ms, p95 159.9 ms, p99 188.8 ms |
| `/telemetry/report`, duplicate events (legacy) | **200.29 rps** | previous 8-worker measurement, comparison only |
| 20-agent fleet, first burst with proof | **341.16 rps** | 20/20 `200`; p50 42.3 ms, p95 52.3 ms |
| 20-agent fleet, 100 warm events | **301.16 rps** | 100/100 `200`; p50 54.2 ms, p95 91.5 ms |
| Legacy agent, first/second report | 79.4 / 38.7 ms | Argon2 once, then persisted proof; 200/200 |

Honest details:

- The "200 rps / 2 workers" gate passes. The old **96–111.58 rps** number came
  from an 8-worker setup, not the Compose default; with 8 workers contention
  increases and it is not the capacity reference.
- `synchronous_commit` remains **on**: there is no durability trade-off. The
  duplicate path remains above 200 rps, but it is not proof of the durable path.
- Cold start no longer uses Argon2 for tokens issued by this version: the
  SHA-256 proof is bound to the Argon2 hash and stored in `agents.meta`.
  Re-enrollment and revocation change the hash, so the old proof no longer
  matches; revocation is still checked against PostgreSQL on every request.
- For legacy tokens, the first contact pays Argon2 and then backfills the proof;
  the second drops to 38.7 ms. This is the accepted behavior for already
  installed agents.
- Reproduction: `AGENT_ENROLL_KEY=... python scripts/bench_ingest.py --events
  3000 --concurrency 30`. For Caddy/TLS, run the client inside the Compose
  network with `aegis.local` resolved to the Caddy container and accept the
  local certificate (`--insecure`).

## Throughput per agent and profiles

| Profile | ev/host/day | Suspicious | Example |
|---|---|---|---|
| light | 5 | 2% | office, 60 s polling |
| normal | 10 | 5% | development, 30 s |
| intensive | 50 | 10% | build server, exec storm |

`scripts/benchmark.py` measures **per-agent** ~500 ev/s in replay; in production
the limit is the network/database, not CPU.

| Scenario | ev/s/agent | Agent CPU | Agent RAM | Traffic | Ingestion latency | Detection latency |
|---|---|---|---|---|---|---|
| 10 agents, 100 ev | 0.5k ev/s | <2% | ~80 MB | 15 KB/s | 2–5 ms (EventSchema) | <0.1 ms |
| 100 agents, 100 ev | 0.5k | <5% | ~120 MB | 150 KB/s | 2–5 ms | <0.1 ms |
| 1,000 agents, 10 ev | 0.4k | <10%* | ~300 MB* | 1.5 MB/s* | 2–5 ms | <0.1 ms |

*The 1,000 agents were simulated in one Python process: CPU/RAM/traffic are
extrapolated, not measured on 1,000 real VMs (hardware limit: 10 parallel
processes tested; 1,000 requires an orchestrator).

## Throughput and scaling (90-day pilot estimate, explicit assumptions)

**Assumptions:** raw JSON event 1.2 KB, index + TOAST + WAL + metadata 0.8 KB →
**2.0 KB/telemetry row**; raw alert 0.5 KB + index 0.5 KB → **1.0 KB/alert**.
A real `pg_total_relation_size` measurement after 10k pilot rows confirms
~1.9–2.1 KB/telemetry row.

| Pilot | Profile | Events | Raw | Indexes | Alerts | **Total** | Average throughput |
|---|---|---|---|---|---|---|---|
| 10 hosts | normal | 9k | 11 MB | 7 MB | 0 MB | **~18 MB** | 0.001 ev/s |
| 100 hosts | normal | 90k | 108 MB | 72 MB | 5 MB | **~185 MB** | 0.01 ev/s |
| 1,000 hosts | intensive | 4.5M | 5,400 MB | 3,600 MB | 225 MB | **~9 GB** | 0.5 ev/s |

90k × 1.2 KB = **108 MB raw** (not 108 KB). With indexes it roughly doubles: the
previous `~150 MB` estimate for 100 hosts was 20% low; the new `~185 MB` includes
PostgreSQL overhead.

Measured peaks: **<10 ev/s** even during an exec storm (eBPF benchmark: 300
execs in 246 ms). Conclusion: a **single `uvicorn --workers 1` worker and a
single PostgreSQL instance are sufficient up to ~300 normal hosts**; beyond that,
async workers and PostgreSQL partitioning are required (see
[`archive/ARCH_REVIEW.md`](archive/ARCH_REVIEW.md)).

## Sensor overhead

- eBPF: **+15% wall-clock** in a worst-case micro-benchmark (`/bin/true` ×300,
  ~0.1 ms/exec, 0 lost, 30 ms total CPU). Negligible under real load.
- Guard user-mode: 1 s scan, hash only new files, netstat ≤5 s, spool bounded at
  50 MB.
- NodeTrace pooling: 10 s heartbeat, batch 25/2 s, 5 s dedup.

## A/B agents 4.3 (2026-11-18)

**Local** live measurement with a fake Brain on `127.0.0.1`, two 8-second runs
per agent, same Windows 11 host, 8 vCPU, Go 1.27.4, Python 3.13.14 and Temurin
25.0.5. Each agent started with pre-seeded identity, so the measurement covers
runtime, not enrollment/CSR. The processes stayed alive for the whole window;
exit code 1 is the harness `terminate()`, not an agent crash. The fake Brain
counts requests but has no PostgreSQL: this is a footprint/startup and live
contract measurement, **not** an ingestion or Brain-latency benchmark.

| Agent | Median RSS | Peak RSS | Median CPU | Artifact |
|---|---:|---:|---:|---:|
| NodeTrace Python (baseline) | **27.28 MB** | 28.15 MB | <0.1% (below resolution) | 34.21 MB bundle |
| Go `sensor` | **18.43 MB** | 18.46 MB | <0.1% | 12.40 MB binary |
| Guard Java 25 (baseline) | **126.45 MB** | 139.33 MB | 4.15% | 18.44 MB JAR + 304.14 MB JRE |
| Go `endpoint` | **18.77 MB** | 19.42 MB | 5.20% | same 12.40 MB binary |

Measured reductions: **−32.4% RSS** for the Go sensor versus NodeTrace and
**−85.2% RSS** for the Go endpoint versus Guard Java. Endpoint CPU is comparable
(5.20% vs 4.15%, two samples with startup noise), and the Go sensor showed no
measurable load. The certain advantage is footprint, not a claimed CPU
percentage: the Go endpoint is not presented as lighter on CPU than Java.

The first endpoint run exposed a real regression: polling read WMI
(cmdline/user) and Authenticode for **every** process every second, saturating a
core. The fix limits expensive fields to new processes; the measurement above is
after the fix. Reproduction: `python scripts/bench_agent_ab.py --runs 2
--duration 8`; raw data in `docs/benchmarks/4.3/agents-ab.json`.

## Live 4.3 profiles (2026-11-19)

This is not a throughput benchmark: it verifies that the same Go binary talks to
the real Brain in all three roles. Compose stack with PostgreSQL, Redis, Brain
and Caddy; Windows agent started from a temporary home, unique hostname, agent
revoked at the end. The Brain recorded **1, 18 and 17 telemetry rows** for
`sensor`, `endpoint` and `unified`, respectively.

| Profile | agent_type | Observed capabilities | Telemetry |
|---|---|---|---:|
| `sensor` | `nodetrace` | telemetry, scan; kernel `absent` on Windows | 1 |
| `endpoint` | `aegis-guard` | FIM, actions, monitor, registry; ETW/YARA unavailable | 18 |
| `unified` | `unified` | both families, one process/outbox | 17 |

The first `unified` start with a single-use token was also tested: token
consumed, record `agent_type=unified`, recent telemetry present. The test does
not install a Windows/Linux service and does not test rollback.

## Queue and resilience

- Encrypted spool 50 MB, ordered replay, 2,000-record RAM bound
  (drop-oldest counted).
- Backpressure visible through `stats()` / `/telemetry/stats` (gaps, duplicates).
- Retry with jitter, `event_id` dedup (LRU 20k), gap detection by
  `(agent,boot,seq)`.
- Reconnect tested in e2e (mTLS required, revocation, wrong CA, renewal).

## Limits

- The 4.3 A/B benchmark is **local and uses a fake Brain**: it does not measure
  PostgreSQL, Caddy/mTLS, a real network or a fleet. The real three-profile
  smoke test was run separately (previous section), but it is not a Brain
  capacity benchmark or fleet proof.
- CPU counts are per second and use two runs: differences below ~2 percentage
  points are not statistically significant.
- Small corpus: **do not claim global 0 FP**; only the documented dataset.
- DB growth is an estimate, not a 90-day real measurement.
- MTTD/triage is live-only (pilot).
- eBPF validated on WSL2 6.6 and Debian bookworm (BTF); a kernel without BTF
  uses partial/fallback mode.
- macOS is build/CI-only; it is not a supported telemetry platform in 4.3.

## Commands

```bash
python scripts/benchmark.py --quick
python scripts/benchmark.py --quick --json   # metadata (Python/OS/CPU/RAM/commit/seed) and p50/p95/p99
python scripts/benchmark.py --agents 100 --events 100
python scripts/generate_corpus_splits.py --dry-run
python scripts/replay_report.py --all --json
python scripts/audit_report.py --skip-slow
python aegis-ebpf/bench.sh                   # eBPF worst-case overhead
```
