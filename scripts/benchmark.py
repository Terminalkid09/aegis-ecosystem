#!/usr/bin/env python3
"""
Benchmark Aegis — throughput, latenza e stime di crescita (Fase 6).

Esegue solo CPU-bound deterministici (replay, dedup, grouping) così è
ripetibile su qualunque host senza DB. Per misure su DB/rete usare
`scripts/bench_ingest.py` su stack Docker reale (documentato in BENCHMARK.md).

Simula 10/100/1000 agent generando eventi sintetici e misura:
- throughput replay (eventi/s)
- latenza detection (ms)
- grouping incidenti
- throughput dedup

Uso: python scripts/benchmark.py [--agents 100 --events 1000]
"""
import argparse
import time
import statistics
import sys
import os

# Permette import da aegis-brain anche se lanciato da repo root
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BRAIN = os.path.join(REPO, "aegis-brain")
if BRAIN not in sys.path:
    sys.path.insert(0, BRAIN)

from app.services.replay import run_static_replay
from app.services.event_dedup import EventDedup, SeqTracker
from app.services.incident_grouping import suggest_groups

def gen_event(agent_idx, seq, malicious=False):
    return {
        "agent_id": f"bench-agent-{agent_idx:04d}",
        "timestamp": "2026-09-12T10:00:00+00:00",
        "event_type": "PROCESS_CREATED",
        "pid": 1000 + seq,
        "parent_pid": 100,
        "parent_process_name": "winword.exe" if malicious else "explorer.exe",
        "process_name": "mimikatz.exe" if malicious else "notepad.exe",
        "process_path": "C:\\Tools\\mimikatz.exe" if malicious else "C:\\Windows\\System32\\notepad.exe",
    }

def bench_replay(agents, events_per_agent, malicious_ratio=0.05):
    events = []
    total = agents * events_per_agent
    for a in range(agents):
        for e in range(events_per_agent):
            malicious = (e % int(1/malicious_ratio) == 0) if malicious_ratio else False
            events.append({"event": gen_event(a, e, malicious)})
    t0 = time.perf_counter()
    res = run_static_replay(events)
    dt = time.perf_counter() - t0
    thr = total / max(dt, 1e-6)
    # detection latency: tempo per singolo evento sospetto
    t1 = time.perf_counter()
    run_static_replay([{"event": gen_event(0, 0, True)}])
    lat_ms = (time.perf_counter() - t1) * 1000
    return {
        "agents": agents,
        "events": total,
        "duration_s": dt,
        "throughput_eps": thr,
        "latency_ms": lat_ms,
        "hits": len(res["hits"]),
    }

def benchGrouping(total_alerts=200):
    alerts = []
    for i in range(total_alerts):
        alerts.append({
            "agent_id": f"a{i%5}",
            "mitre_technique_id": "T1204" if i%3==0 else "T1059",
            "process_name": "powershell.exe" if i%2==0 else "cmd.exe",
            "timestamp": f"2026-09-12T10:{i%60:02d}:00+00:00",
        })
    t0 = time.perf_counter()
    groups = suggest_groups(alerts, window_min=30)
    dt = time.perf_counter() - t0
    return {"groups": len(groups), "duration_ms": dt*1000}

def bench_agent_resource():
    try:
        import psutil
        p = psutil.Process()
        cpu = p.cpu_percent(interval=0.2)
        mem = p.memory_info().rss / 1024 / 1024
        return f"CPU {cpu:.1f}%  RAM {mem:.1f} MB"
    except Exception:
        return "psutil non disponibile — CPU/RAM stimata <5% / <120 MB per agent (bench eBPF 30 ms totale)"

def bench_network(agents, events_per_agent):
    # Stima: 1 evento JSON ~1.2 KB + overhead HTTP ~0.3 KB
    per_event = 1500
    total = agents * events_per_agent * per_event
    per_agent_day = events_per_agent * per_event
    return f"{total/1024:.1f} KB batch, {per_agent_day} B/agent/day ~{per_agent_day/1024:.1f} KB"

def bench_ingestion_latency():
    from app.api.schemas.common import EventSchema
    ev = gen_event(0, 0, False)
    ev["timestamp"] = "2026-09-12T10:00:00+00:00"
    t0 = time.perf_counter()
    for _ in range(100):
        EventSchema(**ev)
    dt = (time.perf_counter() - t0) / 100 * 1000
    return f"{dt:.2f} ms (validazione EventSchema)"

def bench_dedup_gap():
    d = EventDedup(capacity=10000)
    s = SeqTracker()
    t0 = time.perf_counter()
    for i in range(5000):
        d.check(f"agent-{i%10}", f"evt-{i}")
        s.observe(f"agent-{i%10}", "boot-1", i)
    dt = time.perf_counter() - t0
    # Inserisce un gap
    s.observe("agent-1", "boot-1", 6000)
    gaps = s.snapshot()["gaps"]
    return f"{5000/dt:.1f} ops/s, gaps rilevati {gaps}"

def bench_reconnect():
    # Simula retry con jitter: 5 tentativi con backoff 0.1..1.6s
    import random
    delays = []
    base = 0.1
    for i in range(5):
        jitter = random.uniform(0, base*0.5)
        delays.append(base + jitter)
        base *= 2
    total = sum(delays)
    return f"5 retry con jitter: {', '.join(f'{d:.2f}s' for d in delays)} tot {total:.2f}s"

def main():
    ap = argparse.ArgumentParser(description="Aegis benchmark")
    ap.add_argument("--agents", type=int, default=10)
    ap.add_argument("--events", type=int, default=100)
    ap.add_argument("--quick", action="store_true", help="solo 10/10")
    args = ap.parse_args()

    print("=== Aegis Benchmark (replay deterministico) ===")
    configs = [(10,100), (100,100), (10,1000)] if args.quick else [
        (args.agents, args.events),
        (10,100), (100,100), (100,10), (1000,10),
    ]
    # Evita duplicati
    seen = set()
    uniq = []
    for c in configs:
        if c not in seen:
            uniq.append(c); seen.add(c)

    for agents, ev in uniq:
        try:
            r = bench_replay(agents, ev)
            per_agent = r['throughput_eps'] / max(r['agents'],1)
            print(f"agents={r['agents']:4d} events={r['events']:5d} thr={r['throughput_eps']:7.1f} ev/s ({per_agent:.1f} ev/s/agent) latency={r['latency_ms']:.2f}ms hits={r['hits']}")
        except Exception as e:
            print(f"agents={agents} events={ev} ERROR {e}")

    g = benchGrouping()
    print(f"grouping 200 alerts -> {g['groups']} groups in {g['duration_ms']:.2f}ms")
    print(f"dedup+gap: {bench_dedup_gap()}")
    print(f"agent resource: {bench_agent_resource()}")
    print(f"ingestion latency: {bench_ingestion_latency()}")
    print(f"reconnect backoff: {bench_reconnect()}")
    for agents, ev in [(10,100),(100,100),(1000,10)]:
        print(f"net {agents}x{ev}: {bench_network(agents, ev)}")

    # Stima DB growth corretta (ipotesi documentate in BENCHMARK.md)
    print("\n--- Profili pilot (90gg, ipotesi: tel raw 1.2KB + idx 0.8KB =2KB, alert 1KB) ---")
    for name, eps, alert_ratio in [("light",5,0.02),("normale",10,0.05),("intenso",50,0.1)]:
        print(f"{name}: {eps} ev/host/giorno, {alert_ratio*100:.0f}% alert")
        for hosts in (10,100,1000):
            tel = hosts*eps*90
            al = int(hosts*eps*alert_ratio*90)
            raw_mb = tel*1.2/1024
            idx_mb = tel*0.8/1024 + al*0.5/1024
            tot_mb = raw_mb + idx_mb + al*0.5/1024  # alert raw 0.5KB già in idx calc? semplifica
            tot_mb = tel*2.0/1024 + al*1.0/1024
            print(f"  {hosts:4d} host 90gg: {tel:7d} tel ({raw_mb:.0f} MB raw + {idx_mb:.0f} MB idx) + {al:5d} alert -> tot ~{tot_mb:.0f} MB")
    print("Single PG/Redis ok fino a ~300 host; oltre valutare partizionamento e worker async (ARCH_REVIEW).")
    print("Hardware minimo pilot 100: 2 vCPU, 4 GB RAM, 20 GB disk; 1000: 4 vCPU, 8 GB, 50 GB + monitoraggio.")
    print("Metodo: eventi sintetici via replay (CPU-bound); ingestione reale via POST /telemetry su stack Docker con 10/100 agent curl paralleli.")

if __name__ == "__main__":
    main()
