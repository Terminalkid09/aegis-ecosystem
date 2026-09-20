"""Benchmark helpers e contratti di performance (Fase 6).

Misura in modo deterministico (senza DB/rete) i costi computazionali:
- throughput replay (eventi/s)
- latenza detection (da evento ad alert)
- overhead coda/spool

I benchmark su DB/rete/DB-growth sono documentati in docs/BENCHMARK.md e
eseguiti manualmente su stack Docker (non in CI per non flakare).

Tutti i test qui DEVONO passare in <2s su qualunque host CI.
"""
import time
from app.services.replay import run_static_replay, score_corpus
from app.services.event_dedup import EventDedup, SeqTracker
from app.services.incident_grouping import beacon_verdict

def _bench_event(i: int):
    return {
        "agent_id": "bench-host",
        "timestamp": "2026-09-12T10:00:00+00:00",
        "event_type": "PROCESS_CREATED",
        "pid": 1000 + i,
        "process_name": "notepad.exe" if i % 10 else "mimikatz.exe",
        "process_path": "C:\\Windows\\System32\\notepad.exe" if i % 10 else "C:\\Tools\\mimikatz.exe",
    }

def test_replay_throughput_1000():
    events = [{"event": _bench_event(i)} for i in range(1000)]
    t0 = time.perf_counter()
    res = run_static_replay(events)
    dt = time.perf_counter() - t0
    # Su CI WRange tipico <0.4s per 1000; soglia lasca per non flakare.
    assert dt < 2.0, f"replay 1000 troppo lento: {dt:.3f}s"
    assert res["events"] == 1000
    # Throughput informativo (non assert rigido).
    thr = 1000 / max(dt, 0.001)
    assert thr > 200, f"throughput sospettamente basso: {thr:.1f} ev/s"

def test_detection_latency_single():
    ev = _bench_event(0)
    ev["process_name"] = "mimikatz.exe"
    t0 = time.perf_counter()
    res = run_static_replay([{"event": ev}])
    dt_ms = (time.perf_counter() - t0) * 1000
    assert len(res["hits"]) >= 1
    # Latenza detection pura (senza I/O) deve essere microsecondi.
    assert dt_ms < 50, f"latenza single-event troppo alta: {dt_ms:.2f}ms"

def test_dedup_gap_throughput():
    d = EventDedup(capacity=5000)
    s = SeqTracker()
    t0 = time.perf_counter()
    for i in range(5000):
        d.check(f"agent-{i%10}", f"evt-{i}")
        s.observe(f"agent-{i%10}", "boot-1", i)
    dt = time.perf_counter() - t0
    assert dt < 1.0
    assert d.snapshot()["accepted"] == 5000
    assert s.snapshot()["tracked"] == 5000

def test_beacon_verdict_latency():
    ts = [1000.0 + i * 60.0 for i in range(20)]
    t0 = time.perf_counter()
    for _ in range(1000):
        beacon_verdict(ts)
    dt = time.perf_counter() - t0
    assert dt < 1.0

def test_corpus_precision_limits_documented():
    rep = score_corpus()
    # Corpus attuale: 12 benigni + 12 sospetti = 1 host-day sintetico.
    # Non è un dataset di produzione: dichiariamo i limiti, non 0 FP globale.
    assert rep["benign_lines"] == 12
    assert rep["suspicious_lines"] == 12
    assert rep["host_days_assumption"] == 1.0
    assert rep["false_positives_per_host_day"] == 0.0
    assert rep["precision"] == 1.0 and rep["recall"] == 1.0
    # MTTD non misurabile in replay
    assert rep["mttd_seconds"] is None
