#!/usr/bin/env python3
"""Benchmark HTTP riproducibile dell'ingestione agenti su uno stack vivo.

Misura il percorso reale: enrollment con la chiave statica, autenticazione
device, rate limit, dedup Redis, scrittura e commit PostgreSQL. Non usa il DB
direttamente e non simula il brain: se lo stack non regge, il numero lo dice.

Esempi:
    AGENT_ENROLL_KEY=... python scripts/bench_ingest.py --events 1000
    AGENT_ENROLL_KEY=... python scripts/bench_ingest.py \
        --events 1000 --concurrency 40 --batch-size 20
    AGENT_ENROLL_KEY=... python scripts/bench_ingest.py \
        --events 400 --duplicate --path /api/v1/telemetry/report

Il report include throughput eventi/richieste, p50/p95/p99 end-to-end e la
distribuzione degli status. La latenza include l'accodamento del client: è
quella che vede un agente, non solo il tempo CPU dell'handler.
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import statistics
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests


def _event(agent_id: str, event_id: str) -> dict:
    return {
        "agent_id": agent_id,
        "event_id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "SYSTEM_METRICS",
        "cpu_usage": 12.5,
        "ram_usage": 33.0,
        "disk_free": 1_000_000,
        "disk_total": 2_000_000,
    }


def enroll(base: str, key: str, timeout: float, insecure: bool = False) -> tuple[str, str]:
    host = f"ingest-bench-{uuid.uuid4().hex[:12]}"
    r = requests.post(
        f"{base}/api/v1/enroll/enroll",
        json={
            "hostname": host,
            "os": "Linux",
            "enroll_key": key,
            "agent_type": "nodetrace",
        },
        timeout=timeout,
        verify=not insecure,
    )
    r.raise_for_status()
    data = r.json()
    return data["agent_id"], data["agent_secret"]


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, int(round((p / 100.0) * (len(ordered) - 1)))))
    return ordered[idx]


def run(args: argparse.Namespace) -> dict:
    base = args.base.rstrip("/")
    if args.agent_id or args.secret:
        if not (args.agent_id and args.secret):
            raise SystemExit("--agent-id e --secret vanno passati insieme")
        agent_id, secret = args.agent_id, args.secret
    else:
        key = args.enroll_key or os.getenv("AGENT_ENROLL_KEY", "")
        if not key:
            raise SystemExit("AGENT_ENROLL_KEY mancante (env o --enroll-key)")
        agent_id, secret = enroll(base, key, args.timeout, args.insecure)
    headers = {"X-Agent-Id": agent_id, "Authorization": f"Bearer {secret}"}
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Una richiesta calda per worker: l'Argon2 freddo è misurato a parte, non
    # deve sporcare il throughput del percorso già autenticato.
    warm = requests.Session()
    warm.trust_env = False
    warm.verify = not args.insecure
    if args.host_header:
        warm.headers["Host"] = args.host_header
    for _ in range(args.warmup):
        body = _event(agent_id, str(uuid.uuid4()))
        if args.batch_size > 1:
            body = [body]
        rr = warm.post(f"{base}{args.path}", json=body, headers=headers, timeout=args.timeout)
        if rr.status_code != 200:
            raise SystemExit(f"warmup failed: HTTP {rr.status_code}: {rr.text[:200]}")
    warm.close()
    time.sleep(args.settle)

    request_count = (args.events + args.batch_size - 1) // args.batch_size
    work: queue.Queue[int] = queue.Queue()
    for i in range(request_count):
        work.put(i)

    latencies: list[float] = []
    codes: dict[str, int] = {}
    accepted = 0
    errors: list[str] = []
    lock = threading.Lock()
    start = threading.Event()
    fixed_id = str(uuid.uuid4())

    def worker() -> None:
        session = requests.Session()
        session.trust_env = False
        session.verify = not args.insecure
        if args.host_header:
            session.headers["Host"] = args.host_header
        # Connessione stabilita prima del timer: la latenza non include il
        # primo handshake TCP, come in un agente che ha già una sessione.
        session.get(f"{base}/health/live", timeout=args.timeout)
        start.wait()
        nonlocal accepted
        while True:
            try:
                idx = work.get_nowait()
            except queue.Empty:
                return
            n_events = min(args.batch_size, args.events - idx * args.batch_size)
            batch = [
                _event(agent_id, fixed_id if args.duplicate else str(uuid.uuid4()))
                for _ in range(n_events)
            ]
            body = batch if args.batch_size > 1 else batch[0]
            t0 = time.perf_counter()
            try:
                rr = session.post(
                    f"{base}{args.path}", json=body, headers=headers, timeout=args.timeout
                )
                elapsed = (time.perf_counter() - t0) * 1000.0
                with lock:
                    latencies.append(elapsed)
                    codes[str(rr.status_code)] = codes.get(str(rr.status_code), 0) + 1
                    if rr.status_code == 200:
                        payload = rr.json() if rr.content else {}
                        accepted += int(payload.get("accepted", n_events))
                    else:
                        errors.append(f"HTTP {rr.status_code}: {rr.text[:160]}")
            except Exception as exc:  # noqa: BLE001 - il benchmark deve riportare
                with lock:
                    codes["exception"] = codes.get("exception", 0) + 1
                    errors.append(str(exc)[:160])
            finally:
                work.task_done()
        session.close()

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = [pool.submit(worker) for _ in range(args.concurrency)]
        start.set()
        for future in futures:
            future.result()
    elapsed = time.perf_counter() - t0

    return {
        "base": base,
        "path": args.path,
        "agent_id": agent_id,
        "events_requested": args.events,
        "events_accepted": accepted,
        "requests": len(latencies),
        "concurrency": args.concurrency,
        "batch_size": args.batch_size,
        "duplicate": args.duplicate,
        "elapsed_s": round(elapsed, 3),
        "events_per_s": round(accepted / elapsed, 2) if elapsed else 0.0,
        "requests_per_s": round(len(latencies) / elapsed, 2) if elapsed else 0.0,
        "codes": codes,
        "p50_ms": round(_pct(latencies, 50), 1),
        "p95_ms": round(_pct(latencies, 95), 1),
        "p99_ms": round(_pct(latencies, 99), 1),
        "max_ms": round(max(latencies), 1) if latencies else 0.0,
        "errors": errors[:5],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Benchmark ingestione Aegis")
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--host-header", default="",
                    help="Host header (es. aegis.local per Caddy su 127.0.0.1)")
    ap.add_argument("--insecure", action="store_true",
                    help="non verificare il certificato TLS locale")
    ap.add_argument("--path", default="/api/v1/telemetry/report")
    ap.add_argument("--events", type=int, default=1000)
    ap.add_argument("--concurrency", type=int, default=40)
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--warmup", type=int, default=8)
    ap.add_argument("--settle", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--duplicate", action="store_true")
    ap.add_argument("--enroll-key", default="")
    ap.add_argument("--agent-id", default="")
    ap.add_argument("--secret", default="")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    if args.events < 1 or args.concurrency < 1 or args.batch_size < 1:
        ap.error("events, concurrency e batch-size devono essere > 0")
    if args.batch_size > 100:
        ap.error("batch-size massimo 100 (limite server)")
    result = run(args)
    print(json.dumps(result, indent=2))
    return 0 if result["codes"].get("200") == result["requests"] else 1


if __name__ == "__main__":
    sys.exit(main())
