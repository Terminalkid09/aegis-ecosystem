#!/usr/bin/env python3
"""Run a bounded soak (7 days by default) and produce auditable evidence.

A soak is not a load test that runs for a few minutes: it keeps synthetic agents
enrolled and reporting for days while sampling readiness, lost-event counters
and container memory. It detects slow leaks, restarts, queue growth and silent
loss that a short test cannot see. It does not prove detection quality or
malware isolation; those are separate gates.

This runner is deliberately conservative:
- it only uses the existing ``pilot_soak.py`` synthetic agents;
- it never targets a URL other than ``--base``;
- it writes JSONL samples and a final JSON report under ``--out-dir``;
- it fails when the server loses events, readiness is not stable, or a sampled
  container exceeds the allowed RSS growth.

Example (dedicated pilot stack, 20 agents, daily evidence):
    python scripts/soak_7d.py --agents 20 --duration 7d \
      --base https://aegis.local --out-dir artifacts/soak-2026-11

The script needs ``AGENT_ENROLL_KEY`` in the environment or ``.env``.
On Windows, run it in the repository root with the same Python used by tests.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DURATION_RE = re.compile(r"^(\d+)([smhd])$")
MEM_RE = re.compile(r"^\s*([\d.]+)\s*([KMGTP]?i?B)\s*/\s*", re.IGNORECASE)
_UNITS = {
    "B": 1,
    "KB": 1000, "KIB": 1024,
    "MB": 1000**2, "MIB": 1024**2,
    "GB": 1000**3, "GIB": 1024**3,
    "TB": 1000**4, "TIB": 1024**4,
}


def parse_duration(value: str) -> int:
    """Parse ``7d``/``12h``/``300s`` into seconds. Reject ambiguous values."""
    match = DURATION_RE.fullmatch((value or "").strip().lower())
    if not match:
        raise ValueError("duration must look like 7d, 12h, 30m or 300s")
    amount = int(match.group(1))
    unit = match.group(2)
    if amount <= 0:
        raise ValueError("duration must be greater than zero")
    return amount * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


def parse_mem_bytes(value: str) -> int | None:
    """Parse the ``MemUsage`` field from ``docker stats`` (e.g. ``123.4MiB``)."""
    match = MEM_RE.match(value or "")
    if not match:
        return None
    number, unit = match.group(1), match.group(2).upper()
    factor = _UNITS.get(unit)
    if factor is None:
        return None
    return int(float(number) * factor)


def parse_lost(text: str) -> int:
    """Sum every ``aegis_events_lost_total`` sample, including labelled series."""
    total = 0
    for line in text.splitlines():
        if line.startswith("aegis_events_lost_total"):
            try:
                total += int(float(line.split()[-1]))
            except (ValueError, IndexError):
                continue
    return total


def _get(url: str, timeout: float = 10) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # network is part of the measurement
        return 0, str(exc)


def sample_health(base: str) -> bool:
    status, _ = _get(base.rstrip("/") + "/health/ready")
    return status == 200


def sample_lost(base: str) -> int | None:
    status, text = _get(base.rstrip("/") + "/metrics")
    return parse_lost(text) if status == 200 else None


def sample_containers(containers: list[str]) -> dict[str, int]:
    """Return current RSS bytes per container; empty when Docker is unavailable."""
    if not containers:
        return {}
    command = [
        "docker", "stats", "--no-stream", "--format", "{{json .}}",
        *containers,
    ]
    try:
        result = subprocess.run(
            command, check=False, text=True, capture_output=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if result.returncode != 0:
        return {}
    out: dict[str, int] = {}
    for line in result.stdout.splitlines():
        try:
            row = json.loads(line)
            name = str(row.get("Name") or row.get("Container") or "")
            value = parse_mem_bytes(str(row.get("MemUsage") or ""))
            if name and value is not None:
                out[name] = value
        except (ValueError, TypeError, json.JSONDecodeError):
            continue
    return out


def evaluate(report: dict[str, Any], max_rss_growth_mb: float | None) -> list[str]:
    """Return human-readable failures; an empty list means the soak passed."""
    failures: list[str] = []
    if report.get("enroll_fail", 0):
        failures.append(f"enrollment failures: {report['enroll_fail']}")
    if report.get("reports", 0) < 1 or report.get("accepted", 0) < 1:
        failures.append("no new telemetry report was accepted during the soak")
    if report.get("heartbeat", 0) < 1:
        failures.append("no heartbeat was sent during the soak")
    if report.get("errors", 0):
        failures.append(f"HTTP errors: {report['errors']}")
    if report.get("lost_delta") != 0:
        failures.append(f"server lost delta is {report.get('lost_delta')!r}, expected 0")
    if report.get("health_failures", 0):
        failures.append(f"readiness failures: {report['health_failures']}")
    if max_rss_growth_mb is not None:
        for name, growth in report.get("rss_growth_mb", {}).items():
            if growth is not None and growth > max_rss_growth_mb:
                failures.append(
                    f"container {name} grew {growth:.1f} MiB "
                    f"(limit {max_rss_growth_mb:.1f} MiB)"
                )
    return failures


def _load_enroll_key() -> str:
    key = os.getenv("AGENT_ENROLL_KEY", "").strip()
    if key:
        return key
    try:
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("AGENT_ENROLL_KEY="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def _write_jsonl(path: Path, row: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agents", type=int, default=10)
    parser.add_argument("--duration", default="7d", help="7d, 12h, 300s")
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--sample-interval", type=float, default=300,
                        help="seconds between samples (default 300)")
    parser.add_argument("--out-dir", type=Path, default=Path("artifacts/soak"))
    parser.add_argument("--containers", default="aegis-brain,aegis-link",
                        help="comma-separated Docker containers for RSS sampling")
    parser.add_argument("--max-rss-growth-mb", type=float, default=128.0,
                        help="fail if a container grows more than this; 0 disables")
    parser.add_argument("--require-docker", action="store_true",
                        help="fail if Docker RSS sampling is unavailable")
    parser.add_argument("--tag", default=datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S"))
    args = parser.parse_args(argv)

    try:
        duration = parse_duration(args.duration)
    except ValueError as exc:
        print(f"invalid --duration: {exc}", file=sys.stderr)
        return 2
    if args.agents < 1 or args.sample_interval <= 0:
        print("--agents and --sample-interval must be positive", file=sys.stderr)
        return 2
    enroll_key = _load_enroll_key()
    if not enroll_key:
        print("AGENT_ENROLL_KEY missing (environment or .env)", file=sys.stderr)
        return 2
    if duration > 86400 * 30:
        print("refusing an unusually long soak (>30d); split it into runs", file=sys.stderr)
        return 2

    # Import after argument checks so --help does not require the Brain package.
    sys.path.insert(0, str(ROOT / "scripts"))
    from pilot_soak import agent_worker  # type: ignore

    containers = [item.strip() for item in args.containers.split(",") if item.strip()]
    out_dir = args.out_dir if args.out_dir.is_absolute() else ROOT / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    samples_path = out_dir / f"soak-{args.tag}.jsonl"
    report_path = out_dir / f"soak-{args.tag}.json"
    lost_before = sample_lost(args.base)
    stats = {"enroll_fail": 0, "heartbeat": 0, "reports": 0,
             "accepted": 0, "duplicates": 0, "errors": 0}
    lock = threading.Lock()
    stop_at = time.monotonic() + duration
    threads = [
        threading.Thread(
            target=agent_worker,
            args=(args.base, enroll_key, f"{args.tag}-{index}", stop_at, stats, lock),
            daemon=True,
            name=f"soak-agent-{index}",
        )
        for index in range(args.agents)
    ]
    started = time.monotonic()
    for thread in threads:
        thread.start()

    health_failures = 0
    samples = 0
    rss_first: dict[str, int] = {}
    rss_max: dict[str, int] = {}
    docker_available = True
    try:
        while time.monotonic() < stop_at:
            now = time.monotonic()
            healthy = sample_health(args.base)
            if not healthy:
                health_failures += 1
            lost = sample_lost(args.base)
            mem = sample_containers(containers)
            if not mem and args.require_docker:
                print("Docker RSS sampling unavailable", file=sys.stderr)
                return 3
            if not mem:
                docker_available = False
            for name, value in mem.items():
                rss_first.setdefault(name, value)
                rss_max[name] = max(rss_max.get(name, 0), value)
            with lock:
                snapshot = dict(stats)
            _write_jsonl(samples_path, {
                "at": datetime.now(timezone.utc).isoformat(),
                "elapsed_s": round(now - started, 1),
                "healthy": healthy,
                "lost": lost,
                "stats": snapshot,
                "rss_bytes": mem,
            })
            samples += 1
            remaining = stop_at - time.monotonic()
            if remaining > 0:
                time.sleep(min(args.sample_interval, remaining))
    finally:
        for thread in threads:
            thread.join(timeout=max(1.0, stop_at - time.monotonic()) + 5)
    elapsed = time.monotonic() - started
    lost_after = sample_lost(args.base)
    lost_delta = (
        lost_after - lost_before
        if lost_before is not None and lost_after is not None
        else None
    )
    with lock:
        final_stats = dict(stats)
    growth_mb: dict[str, float] = {}
    for name, first in rss_first.items():
        growth_mb[name] = round((rss_max.get(name, first) - first) / (1024 * 1024), 2)
    report = {
        "schema": "aegis-soak-v1",
        "tag": args.tag,
        "base": args.base,
        "started_at": datetime.fromtimestamp(
            time.time() - elapsed, timezone.utc).isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "requested_duration_s": duration,
        "elapsed_s": round(elapsed, 1),
        "agents": args.agents,
        "samples": samples,
        "samples_path": str(samples_path),
        "docker_available": docker_available,
        "containers": containers,
        "lost_before": lost_before,
        "lost_after": lost_after,
        "lost_delta": lost_delta,
        "health_failures": health_failures,
        "rss_first_bytes": rss_first,
        "rss_max_bytes": rss_max,
        "rss_growth_mb": growth_mb,
        **final_stats,
        "max_rss_growth_mb": args.max_rss_growth_mb if args.max_rss_growth_mb > 0 else None,
    }
    failures = evaluate(report, report["max_rss_growth_mb"])
    report["failures"] = failures
    report["passed"] = not failures
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "report": str(report_path),
                      "failures": failures}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
