#!/usr/bin/env python3
"""Validate operator-supplied AP-126 detonation evidence (fail-closed).

AP-126 is not "run a malware sample in Docker". A valid result needs an
authorized sample, an isolated lab with a snapshot/restore, a verified kill
switch, no public network and a recorded process tree. Those are external
inputs; this gate refuses to turn a partial or synthetic run into a PASS.

Input example:
{
  "schema": "aegis-ap126-evidence-v1",
  "sample": {"sha256": "<64 hex>", "authorized": true},
  "authorization": {"authorized_by": "name", "expires_at": "2026-12-01T00:00:00Z"},
  "lab": {"isolated": true, "network": "deny-all", "snapshot_id": "snap-...",
           "snapshot_restored": true, "restore_verified": true},
  "execution": {"kill_switch_verified": true, "timeout_enforced": true,
                 "process_tree_recorded": true},
  "observations": {"dropped_files": 0, "network_connections": 0}
}
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def validate(doc: dict[str, Any], sample: Path | None = None) -> list[str]:
    failures: list[str] = []
    if doc.get("schema") != "aegis-ap126-evidence-v1":
        failures.append("schema must be aegis-ap126-evidence-v1")
    digest = str(doc.get("sample", {}).get("sha256", "")).lower()
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        failures.append("sample.sha256 must be a 64-character hex digest")
    if not doc.get("sample", {}).get("authorized"):
        failures.append("sample.authorized is false")
    auth = doc.get("authorization", {})
    if not str(auth.get("authorized_by", "")).strip():
        failures.append("authorization.authorized_by is empty")
    try:
        expires = datetime.fromisoformat(str(auth.get("expires_at", "")).replace("Z", "+00:00"))
        if expires <= datetime.now(timezone.utc):
            failures.append("authorization is expired")
    except ValueError:
        failures.append("authorization.expires_at is not ISO-8601")
    lab = doc.get("lab", {})
    if lab.get("isolated") is not True:
        failures.append("lab.isolated must be true")
    if str(lab.get("network", "")) not in {"deny-all", "none", "isolated"}:
        failures.append("lab.network must be deny-all/none/isolated")
    if not str(lab.get("snapshot_id", "")).strip():
        failures.append("lab.snapshot_id is missing")
    for key in ("snapshot_restored", "restore_verified"):
        if lab.get(key) is not True:
            failures.append(f"lab.{key} must be true")
    execution = doc.get("execution", {})
    for key in ("kill_switch_verified", "timeout_enforced", "process_tree_recorded"):
        if execution.get(key) is not True:
            failures.append(f"execution.{key} must be true")
    observations = doc.get("observations", {})
    try:
        connections = int(observations.get("network_connections", 0))
    except (TypeError, ValueError):
        connections = -1
    if connections != 0:
        failures.append("observations.network_connections must be 0")
    if sample is not None:
        actual = hashlib.sha256(sample.read_bytes()).hexdigest()
        if actual != digest:
            failures.append(f"sample SHA-256 mismatch: evidence {digest}, file {actual}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--sample", type=Path, help="verify the authorized file hash too")
    parser.add_argument("--enforce", action="store_true")
    args = parser.parse_args()
    doc = json.loads(args.evidence.read_text(encoding="utf-8"))
    failures = validate(doc, args.sample)
    print(json.dumps({"passed": not failures, "failures": failures}, indent=2))
    if failures and args.enforce:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
