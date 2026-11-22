"""Release signing guard tests, no tag or release operation."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "release_smoke", ROOT / "scripts" / "release-smoke.py"
)
assert SPEC and SPEC.loader
release_smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_smoke)


def _sidecar(path: Path, **values) -> None:
    path.write_text(json.dumps(values), encoding="utf-8")


def test_release_rejects_test_and_unsigned_packages(tmp_path: Path) -> None:
    _sidecar(tmp_path / "a.msi.signing.json",
             schema="aegis-package-signing-v1", package="a.msi",
             mode="test", status="UnknownError", timestamp=None)
    failures = release_smoke.check_signing_sidecars(tmp_path)
    assert failures and "expected production" in failures[0]

    _sidecar(tmp_path / "a.msi.signing.json",
             schema="aegis-package-signing-v1", package="a.msi",
             mode="unsigned", status="NotSigned", timestamp=None)
    assert release_smoke.check_signing_sidecars(tmp_path)


def test_release_accepts_only_a_valid_timestamped_production_msi(tmp_path: Path) -> None:
    _sidecar(tmp_path / "ok.msi.signing.json",
             schema="aegis-package-signing-v1", package="ok.msi",
             mode="production", status="Valid", timestamp="2026-11-22T00:00:00Z")
    assert release_smoke.check_signing_sidecars(tmp_path) == []

    _sidecar(tmp_path / "naked.msi.signing.json",
             schema="aegis-package-signing-v1", package="naked.msi",
             mode="production", status="Valid", timestamp=None)
    failures = release_smoke.check_signing_sidecars(tmp_path)
    assert any("timestamp" in item for item in failures)
