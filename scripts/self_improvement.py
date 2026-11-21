#!/usr/bin/env python3
"""Governed detection-candidate pipeline (no autonomous self-modification).

Self-improvement here means a repeatable, auditable loop, not a model that
rewrites production rules by itself:

    candidate -> offline corpus evaluation -> threshold gate -> human approval
              -> signed promotion record -> canary/rollback state

The script never edits the live rule files. It emits a signed promotion record
and, optionally, a canary descriptor that the operator's deployment process can
consume. Every promotion needs ``--approved-by`` and ``--approval-ticket`` and a
private signing key. A candidate that fails the corpus gate cannot be promoted.

Example:
    PYTHONPATH=aegis-brain .venv315/Scripts/python.exe \\
      scripts/self_improvement.py evaluate candidate.json \\
        --corpus real-corpus.jsonl --min-recall 0.95 --max-fpr 0.05

    scripts/self_improvement.py promote candidate.json --corpus real-corpus.jsonl \\
      --approved-by security-lead --approval-ticket CHG-123 \\
      --signing-key /secure/aegis-detection-signing.pem \\
      --state-dir dist/detection-state --canary
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def load_candidate(path: Path) -> dict[str, Any]:
    row = json.loads(path.read_text(encoding="utf-8"))
    required = {"schema", "rule_id", "version", "field", "pattern", "severity"}
    missing = required - set(row)
    if missing:
        raise SystemExit(f"candidate missing fields: {sorted(missing)}")
    if row["schema"] != "aegis-detection-candidate-v1":
        raise SystemExit("candidate schema must be aegis-detection-candidate-v1")
    if not isinstance(row["field"], str) or not isinstance(row["pattern"], str):
        raise SystemExit("candidate field/pattern must be strings")
    try:
        re.compile(row["pattern"])
    except re.error as exc:
        raise SystemExit(f"candidate regex is invalid: {exc}") from exc
    return row


def load_corpus(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"invalid corpus JSON on line {lineno}: {exc}") from exc
        if row.get("label") not in {"malicious", "benign"} or not isinstance(row.get("event"), dict):
            raise SystemExit(f"line {lineno}: label must be malicious|benign and event an object")
        rows.append(row)
    if not rows:
        raise SystemExit("corpus is empty")
    return rows


def _field_value(event: dict[str, Any], field: str) -> str:
    current: Any = event
    for part in field.split("."):
        if not isinstance(current, dict):
            return ""
        current = current.get(part)
    return "" if current is None else str(current)


def evaluate(candidate: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    pattern = re.compile(candidate["pattern"])
    counts = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    results = []
    for row in rows:
        detected = bool(pattern.search(_field_value(row["event"], candidate["field"])))
        malicious = row["label"] == "malicious"
        outcome = "tp" if malicious and detected else "fn" if malicious else "fp" if detected else "tn"
        counts[outcome] += 1
        results.append({
            "label": row["label"],
            "detected": detected,
            "outcome": outcome,
            "hostname": row["event"].get("hostname", "unknown"),
        })
    positives = counts["tp"] + counts["fp"]
    negatives = counts["fp"] + counts["tn"]
    recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 0.0
    fpr = counts["fp"] / negatives if negatives else 0.0
    precision = counts["tp"] / positives if positives else 0.0
    return {
        "schema": "aegis-detection-candidate-eval-v1",
        "rule_id": candidate["rule_id"],
        "version": candidate["version"],
        "samples": len(rows),
        "metrics": {
            **counts,
            "recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
            "precision": round(precision, 4),
        },
        "results": results,
    }


def _sign(data: bytes, key_path: Path) -> tuple[str, str]:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
    except ImportError as exc:
        raise SystemExit("cryptography is required for promotion/rollback signing") from exc
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if isinstance(key, ed25519.Ed25519PrivateKey):
        signature = key.sign(data)
        algorithm = "ed25519"
    elif isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
        algorithm = "rsa-pkcs1v15-sha256"
    else:
        raise SystemExit("unsupported signing key type; use Ed25519 or RSA")
    return base64.b64encode(signature).decode("ascii"), algorithm


def _load_thresholds(args: argparse.Namespace) -> None:
    if not 0 <= args.min_recall <= 1 or not 0 <= args.max_fpr <= 1:
        raise SystemExit("thresholds must be between 0 and 1")


def _offline(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], str]:
    candidate = load_candidate(args.candidate)
    rows = load_corpus(args.corpus)
    report = evaluate(candidate, rows)
    report["corpus_sha256"] = hashlib.sha256(args.corpus.read_bytes()).hexdigest()
    report["corpus"] = str(args.corpus)
    report["thresholds"] = {"min_recall": args.min_recall, "max_fpr": args.max_fpr}
    return candidate, report, report["corpus_sha256"]


def cmd_evaluate(args: argparse.Namespace) -> int:
    _load_thresholds(args)
    _, report, _ = _offline(args)
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(text, encoding="utf-8")
    print(text, end="")
    metrics = report["metrics"]
    failed = metrics["recall"] < args.min_recall or metrics["false_positive_rate"] > args.max_fpr
    if failed:
        print("candidate gate FAILED", file=sys.stderr)
        return 1
    return 0


def cmd_promote(args: argparse.Namespace) -> int:
    _load_thresholds(args)
    if args.state_dir.resolve() == args.corpus.resolve().parent:
        raise SystemExit("state-dir must not be the corpus directory")
    candidate, report, corpus_sha = _offline(args)
    metrics = report["metrics"]
    if metrics["recall"] < args.min_recall or metrics["false_positive_rate"] > args.max_fpr:
        raise SystemExit("refusing promotion: candidate does not meet corpus thresholds")
    if not args.approved_by.strip() or not args.approval_ticket.strip():
        raise SystemExit("approval requires --approved-by and --approval-ticket")
    state_dir = args.state_dir
    state_dir.mkdir(parents=True, exist_ok=True)
    current = state_dir / "current.json"
    previous = state_dir / "previous.json"
    if current.exists():
        shutil.copy2(current, previous)
    record = {
        "schema": "aegis-detection-promotion-v1",
        "candidate": candidate,
        "evaluation": {k: report[k] for k in ("metrics", "samples", "thresholds", "corpus_sha256")},
        "approved_by": args.approved_by,
        "approval_ticket": args.approval_ticket,
        "promoted_at": _now(),
    }
    signature, algorithm = _sign(_canonical(record), args.signing_key)
    record["signature"] = {"algorithm": algorithm, "value": signature}
    (state_dir / "current.json").write_text(
        json.dumps(record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.canary:
        canary = {
            "schema": "aegis-detection-canary-v1",
            "rule_id": candidate["rule_id"],
            "version": candidate["version"],
            "percent": args.canary_percent,
            "created_at": _now(),
            "rollback_to": str(previous) if previous.exists() else None,
            "promotion_sha256": hashlib.sha256(_canonical(record)).hexdigest(),
        }
        (state_dir / "canary.json").write_text(
            json.dumps(canary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "promoted": True, "state": str(current),
        "signature_algorithm": algorithm, "canary": bool(args.canary),
    }, indent=2))
    return 0


def cmd_rollback(args: argparse.Namespace) -> int:
    if not args.approved_by.strip() or not args.approval_ticket.strip():
        raise SystemExit("rollback requires --approved-by and --approval-ticket")
    state_dir = args.state_dir
    current = state_dir / "current.json"
    previous = state_dir / "previous.json"
    if not previous.exists():
        raise SystemExit("no previous promotion to roll back to")
    if not current.exists():
        raise SystemExit("current promotion is missing")
    rejected = state_dir / f"rejected-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    shutil.move(str(current), rejected)
    shutil.copy2(previous, current)
    note = {
        "schema": "aegis-detection-rollback-v1",
        "rolled_back_at": _now(),
        "approved_by": args.approved_by,
        "approval_ticket": args.approval_ticket,
        "rejected_record": str(rejected),
        "restored_record": str(current),
    }
    (state_dir / "rollback.json").write_text(
        json.dumps(note, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"rolled_back": True, "restored": str(current)}, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("evaluate", "promote"):
        p = sub.add_parser(name)
        p.add_argument("candidate", type=Path)
        p.add_argument("--corpus", type=Path, required=True)
        p.add_argument("--min-recall", type=float, default=0.95)
        p.add_argument("--max-fpr", type=float, default=0.05)
        if name == "evaluate":
            p.add_argument("--json-out", type=Path)
            p.set_defaults(func=cmd_evaluate)
        else:
            p.add_argument("--approved-by", required=True)
            p.add_argument("--approval-ticket", required=True)
            p.add_argument("--signing-key", type=Path, required=True)
            p.add_argument("--state-dir", type=Path, default=Path("dist/detection-state"))
            p.add_argument("--canary", action="store_true")
            p.add_argument("--canary-percent", type=int, default=5, choices=range(1, 101))
            p.set_defaults(func=cmd_promote)
    rollback = sub.add_parser("rollback")
    rollback.add_argument("--state-dir", type=Path, default=Path("dist/detection-state"))
    rollback.add_argument("--approved-by", required=True)
    rollback.add_argument("--approval-ticket", required=True)
    rollback.set_defaults(func=cmd_rollback)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
