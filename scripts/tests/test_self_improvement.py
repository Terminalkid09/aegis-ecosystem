"""Unit tests for governed self-improvement evaluation; no live rules touched."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.self_improvement import evaluate


def test_evaluate_counts_and_fails_closed() -> None:
    candidate = {
        "schema": "aegis-detection-candidate-v1",
        "rule_id": "TEST-1", "version": "1.0.0",
        "field": "process_name", "pattern": r"(?i)^evil\.exe$", "severity": "HIGH",
    }
    rows = [
        {"label": "malicious", "event": {"process_name": "evil.exe"}},
        {"label": "malicious", "event": {"process_name": "good.exe"}},
        {"label": "benign", "event": {"process_name": "word.exe"}},
        {"label": "benign", "event": {"process_name": "evil.exe.bak"}},
    ]
    report = evaluate(candidate, rows)
    assert report["metrics"]["tp"] == 1
    assert report["metrics"]["fn"] == 1
    assert report["metrics"]["fp"] == 0
    assert report["metrics"]["tn"] == 2
    assert report["metrics"]["recall"] == 0.5
