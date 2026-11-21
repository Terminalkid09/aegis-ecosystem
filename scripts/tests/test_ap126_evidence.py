"""AP-126 evidence gate tests: synthetic/incomplete evidence must not pass."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.ap126_evidence import validate

HEX = "a" * 64


def _valid() -> dict:
    return {
        "schema": "aegis-ap126-evidence-v1",
        "sample": {"sha256": HEX, "authorized": True},
        "authorization": {"authorized_by": "lab-owner", "expires_at": "2099-01-01T00:00:00Z"},
        "lab": {
            "isolated": True, "network": "deny-all", "snapshot_id": "snap-1",
            "snapshot_restored": True, "restore_verified": True,
        },
        "execution": {
            "kill_switch_verified": True, "timeout_enforced": True,
            "process_tree_recorded": True,
        },
        "observations": {"network_connections": 0},
    }


def test_valid_evidence() -> None:
    assert validate(_valid()) == []


def test_missing_snapshot_and_network_egress_fail() -> None:
    doc = _valid()
    doc["lab"]["snapshot_restored"] = False
    doc["observations"]["network_connections"] = 1
    failures = validate(doc)
    assert any("snapshot_restored" in f for f in failures)
    assert any("network_connections" in f for f in failures)
