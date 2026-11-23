"""Regression tests for the reboot/crash contracts, no host changes."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.persistence_check import static_failures


def test_checked_in_persistence_contracts() -> None:
    assert static_failures() == []
