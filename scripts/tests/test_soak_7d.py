"""Focused unit tests for the soak parser/evaluator; no Brain or Docker needed."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.soak_7d import evaluate, parse_duration, parse_lost, parse_mem_bytes


def test_parse_duration() -> None:
    assert parse_duration("7d") == 7 * 86400
    assert parse_duration("12h") == 12 * 3600
    assert parse_duration("5m") == 300
    for bad in ("7", "d", "0d", "-1d", "7 days"):
        try:
            parse_duration(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted invalid duration {bad!r}")


def test_parse_memory_and_lost() -> None:
    assert parse_mem_bytes("123.5MiB / 1GiB") == int(123.5 * 1024 * 1024)
    assert parse_mem_bytes("512KiB / 1GiB") == 512 * 1024
    assert parse_mem_bytes("n/a") is None
    assert parse_lost(
        'aegis_events_lost_total{reason="consumer"} 2\n'
        "aegis_events_lost_total 3\n"
    ) == 5


def test_evaluate_is_fail_closed() -> None:
    good = {
        "enroll_fail": 0, "reports": 100, "accepted": 100, "heartbeat": 100,
        "errors": 0, "lost_delta": 0,
        "health_failures": 0, "rss_growth_mb": {"aegis-brain": 4.0},
    }
    assert evaluate(good, 128) == []
    bad = {**good, "lost_delta": 1}
    assert any("lost" in item for item in evaluate(bad, 128))
    idle = {**good, "reports": 0, "accepted": 0, "heartbeat": 0}
    assert any("no new telemetry" in item for item in evaluate(idle, 128))
    assert any("no heartbeat" in item for item in evaluate(idle, 128))
    leak = {**good, "rss_growth_mb": {"aegis-brain": 129.0}}
    assert any("grew" in item for item in evaluate(leak, 128))
