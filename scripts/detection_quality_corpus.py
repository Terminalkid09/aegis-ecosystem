#!/usr/bin/env python3
"""Measure AP-127 detection quality on a frozen, labelled corpus.

The corpus is JSONL: each line has a ``label`` of ``malicious`` or ``benign``
and an ``event`` object accepted by the Brain's EventSchema. No malware is
executed; this reads recorded events. A production claim requires real
benign/malicious traffic and the operator's labelled corpus; the command can
run on a synthetic fixture for engine regression only.

Run from the repository root with the Brain on PYTHONPATH:
    PYTHONPATH=aegis-brain .venv315/Scripts/python.exe \
      scripts/detection_quality_corpus.py corpus.jsonl --enforce
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


def _load_rows(path: Path) -> list[dict[str, Any]]:
    rows = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid JSON on line {lineno}: {exc}") from exc
        label = row.get("label")
        event = row.get("event")
        if label not in {"malicious", "benign"} or not isinstance(event, dict):
            raise SystemExit(f"line {lineno}: label must be malicious|benign and event an object")
        rows.append({"label": label, "event": event})
    if not rows:
        raise SystemExit("corpus is empty")
    return rows


def _group_key(event: Any) -> str:
    hostname = str(getattr(event, "hostname", None) or "unknown")
    timestamp = getattr(event, "timestamp", None)
    day = timestamp.date().isoformat() if isinstance(timestamp, datetime) else "unknown"
    return f"{hostname}/{day}"


async def _measure(rows: list[dict[str, Any]]) -> dict[str, Any]:
    from app.api.schemas.common import EventSchema
    from app.rules.heuristic_engine import HeuristicEngine

    engine = HeuristicEngine()
    groups: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0, "tn": 0})
    results = []
    for row in rows:
        event = EventSchema(**row["event"])
        result = await engine.analyze(event)
        detected = bool(result.is_threat)
        malicious = row["label"] == "malicious"
        outcome = "tp" if malicious and detected else "fn" if malicious else "fp" if detected else "tn"
        groups[_group_key(event)][outcome] += 1
        results.append({
            "label": row["label"],
            "detected": detected,
            "outcome": outcome,
            "host_day": _group_key(event),
            "severity": result.severity if detected else "NONE",
        })
    totals = {key: sum(group[key] for group in groups.values()) for key in ("tp", "fn", "fp", "tn")}
    positives = totals["tp"] + totals["fp"]
    negatives = totals["fp"] + totals["tn"]
    recall = totals["tp"] / (totals["tp"] + totals["fn"]) if totals["tp"] + totals["fn"] else 0.0
    fpr = totals["fp"] / negatives if negatives else 0.0
    precision = totals["tp"] / positives if positives else 0.0
    return {
        "schema": "aegis-detection-quality-corpus-v1",
        "samples": len(rows),
        "metrics": {
            **totals,
            "recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
            "precision": round(precision, 4),
        },
        "host_day": dict(groups),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--min-recall", type=float, default=0.95)
    parser.add_argument("--max-fpr", type=float, default=0.05)
    parser.add_argument("--enforce", action="store_true",
                        help="exit 1 when a threshold is not met")
    args = parser.parse_args()
    raw = args.corpus.read_bytes()
    report = asyncio.run(_measure(_load_rows(args.corpus)))
    report["corpus_sha256"] = hashlib.sha256(raw).hexdigest()
    report["corpus"] = str(args.corpus)
    report["thresholds"] = {"min_recall": args.min_recall, "max_fpr": args.max_fpr}
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.json_out:
        args.json_out.write_text(text, encoding="utf-8")
    print(text, end="")
    metrics = report["metrics"]
    failed = metrics["recall"] < args.min_recall or metrics["false_positive_rate"] > args.max_fpr
    if failed and args.enforce:
        print("AP-127 gate FAILED", file=sys.stderr)
        return 1
    if failed:
        print("AP-127 gate would fail; rerun with --enforce for a blocking check", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
