#!/usr/bin/env python3
"""Live load test for the Link ingestion queue (AP-122).

This talks to a running aegis-link over HTTP and, optionally, checks the real
Redis depth. It is deliberately not a unit test: the point is to exercise the
same authenticated controller, JSON validation and atomic Lua push used by an
agent, with enough concurrent producers to expose a check/push race.

For the full-queue test, point Link at a dedicated Redis with no Brain consumer
and disable the overload spool on that instance:

    docker run -d --name aegis-link-load-redis -p 16379:6379 redis:7-alpine
    AEGIS_API_KEY=load-key \
    SPRING_DATA_REDIS_HOST=host.docker.internal \
    SPRING_DATA_REDIS_PORT=16379 \
    AEGIS_LINK_SPOOL_ENABLED=false \
    java -jar aegis-link/target/*.jar

    python scripts/link_load.py \
        --base http://127.0.0.1:8080 \
        --events 50001 --concurrency 128 \
        --api-key load-key --agent-id load-agent \
        --queue-url redis://127.0.0.1:16379/0 --cap 50000

Expected result: 50,000 accepted, one 429, and LLEN == 50,000. A 5xx, an
accepted event when the queue is at the cap, or a depth above the cap fails the
command. The script uses threads only as an HTTP client; it does not create
50,000 routes or agents.
"""
from __future__ import annotations

import argparse
import json
import queue
import statistics
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests


def _event(agent_id: str, hostname: str) -> dict:
    return {
        "agentId": agent_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "eventType": "PROCESS_CREATED",
        "hostname": hostname,
        "os": "Windows",
        "pid": 1234,
        "processName": "load.exe",
    }


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(p / 100 * (len(ordered) - 1)))))
    return ordered[index]


def _queue_depth(url: str) -> int | None:
    if not url:
        return None
    try:
        import redis  # type: ignore
    except ImportError:
        raise SystemExit("--queue-url requires redis-py (pip install redis)")
    client = redis.from_url(url, decode_responses=True)
    try:
        return int(client.llen("aegis:events"))
    finally:
        client.close()


def run(args: argparse.Namespace) -> dict:
    base = args.base.rstrip("/")
    work: queue.Queue[int] = queue.Queue()
    for i in range(args.events):
        work.put(i)

    statuses: dict[str, int] = {}
    accepted = 0
    spooled = 0
    rejected = 0
    server_errors: list[str] = []
    other_errors: list[str] = []
    latencies: list[float] = []
    lock = threading.Lock()
    start = threading.Event()
    hostname = f"load-{uuid.uuid4().hex[:8]}"

    def worker() -> None:
        nonlocal accepted, spooled, rejected
        session = requests.Session()
        session.trust_env = False
        session.headers.update({
            "X-Api-Key": args.api_key,
            "X-Agent-Id": args.agent_id,
            "Content-Type": "application/json",
        })
        start.wait()
        while True:
            try:
                _ = work.get_nowait()
            except queue.Empty:
                break
            t0 = time.perf_counter()
            try:
                response = session.post(
                    f"{base}/api/v1/events",
                    json=_event(args.agent_id, hostname),
                    timeout=args.timeout,
                )
                elapsed_ms = (time.perf_counter() - t0) * 1000
                body = response.json() if response.content else {}
                with lock:
                    latencies.append(elapsed_ms)
                    statuses[str(response.status_code)] = (
                        statuses.get(str(response.status_code), 0) + 1
                    )
                    if response.status_code == 202:
                        accepted += 1
                        if body.get("status") == "spooled":
                            spooled += 1
                    elif response.status_code == 429:
                        rejected += 1
                    elif response.status_code >= 500:
                        server_errors.append(
                            f"{response.status_code}: {response.text[:160]}"
                        )
                    else:
                        other_errors.append(
                            f"{response.status_code}: {response.text[:160]}"
                        )
            except Exception as exc:  # noqa: BLE001 - the report must show it
                with lock:
                    statuses["exception"] = statuses.get("exception", 0) + 1
                    server_errors.append(f"{type(exc).__name__}: {exc}"[:160])
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
    depth = _queue_depth(args.queue_url)

    expected_overflow = max(0, args.events - args.cap)
    result = {
        "base": base,
        "events": args.events,
        "concurrency": args.concurrency,
        "cap": args.cap,
        "statuses": statuses,
        "accepted": accepted,
        "spooled": spooled,
        "rejected_429": rejected,
        "queue_depth": depth,
        "elapsed_s": round(elapsed, 3),
        "requests_per_s": round(args.events / elapsed, 2) if elapsed else 0.0,
        "p50_ms": round(_pct(latencies, 50), 1),
        "p95_ms": round(_pct(latencies, 95), 1),
        "p99_ms": round(_pct(latencies, 99), 1),
        "max_ms": round(max(latencies), 1) if latencies else 0.0,
        "server_errors": server_errors[:5],
        "other_errors": other_errors[:5],
    }

    failures = []
    if server_errors:
        failures.append("5xx or client exception")
    if other_errors:
        failures.append("unexpected HTTP status")
    if accepted > args.cap:
        failures.append("accepted above cap")
    if depth is not None and depth > args.cap:
        failures.append("Redis depth above cap")
    if args.expect_cap:
        if accepted != args.cap:
            failures.append(f"accepted {accepted}, expected {args.cap}")
        if rejected != expected_overflow:
            failures.append(
                f"429 {rejected}, expected {expected_overflow}"
            )
        if depth is not None and depth != args.cap:
            failures.append(f"Redis depth {depth}, expected {args.cap}")

    result["failures"] = failures
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Live Link ingest load test (HTTP + optional Redis check)"
    )
    parser.add_argument("--base", default="http://127.0.0.1:8080")
    parser.add_argument("--events", type=int, default=50001)
    parser.add_argument("--concurrency", type=int, default=128)
    parser.add_argument("--cap", type=int, default=50000)
    parser.add_argument("--api-key", required=True)
    parser.add_argument("--agent-id", default="link-load-agent")
    parser.add_argument("--queue-url", default="")
    parser.add_argument("--expect-cap", action="store_true")
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.events < 1 or args.concurrency < 1 or args.cap < 1:
        parser.error("events, concurrency and cap must be > 0")
    if args.concurrency > 512:
        parser.error("concurrency is capped at 512 to keep the client honest")
    result = run(args)
    print(json.dumps(result, indent=2) if args.json else json.dumps(result, sort_keys=True))
    if result["failures"]:
        print("FAILED: " + "; ".join(result["failures"]), file=sys.stderr)
        return 1
    print("PASS: 50k Link queue boundary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
