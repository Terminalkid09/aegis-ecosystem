"""Release-bundle contract tests.

The release job runs the bundle from a tag checkout, not from a developer
machine. These tests pin the unified-only layout and the two things that broke
in 4.1: the portable environment-template name and the agent checksum surface.
"""
from __future__ import annotations

import importlib.util
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "release-bundle.py"


def _bundle_module():
    spec = importlib.util.spec_from_file_location("release_bundle", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_agent_fixture(agent_dir: Path) -> None:
    (agent_dir / "aegis-agent.exe").write_bytes(b"MZ" + b"\0" * 16)
    (agent_dir / "aegis-agent").write_bytes(b"\x7fELF" + b"\0" * 16)
    (agent_dir / "aegis-etw.exe").write_bytes(b"MZ" + b"\0" * 16)
    (agent_dir / "aegis-collector").write_bytes(b"\x7fELF" + b"\0" * 16)
    (agent_dir / "aegis_exec.bpf.o").write_bytes(b"\x7fELF" + b"\0" * 16)


def test_env_example_has_a_portable_release_name():
    bundle = _bundle_module()
    assert bundle.release_name(".env.example") == "env.example"
    assert bundle.release_name("docs/RELEASE_SIGNING.md") == "RELEASE_SIGNING.md"


def test_core_files_include_signing_decision_and_env_template():
    bundle = _bundle_module()
    assert ".env.example" in bundle.CORE_FILES
    assert "docs/RELEASE_SIGNING.md" in bundle.CORE_FILES


def test_release_workflow_attests_assets_and_keeps_e2e_gate():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "actions/attest-build-provenance@" in workflow
    assert "id-token: write" in workflow
    assert "attestations: write" in workflow
    assert "subject-path:" in workflow
    assert "Compose E2E Gate" in workflow
    assert "scripts/seed_e2e.py" in workflow


def test_agent_assets_ship_only_unified_archives_with_kernel_helpers(tmp_path: Path):
    bundle = _bundle_module()
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    _write_agent_fixture(agent_dir)
    out = tmp_path / "release"
    out.mkdir()

    created = bundle._agent_assets(agent_dir, out, "v4.3.0", True)

    assert set(created) == {
        "unified-latest.zip", "unified-4.3.0.zip",
        "unified-latest.tar.gz", "unified-4.3.0.tar.gz",
    }
    assert not (out / "aegis-agent-windows-amd64.exe").exists()
    assert not (out / "aegis-agent-linux-amd64").exists()
    with zipfile.ZipFile(out / "unified-latest.zip") as zf:
        assert {"aegis-agent.exe", "aegis-etw.exe"} <= set(zf.namelist())
    with tarfile.open(out / "unified-latest.tar.gz") as tf:
        members = {m.name: m for m in tf.getmembers() if m.isfile()}
        assert {"aegis-agent", "aegis-collector", "aegis_exec.bpf.o"} <= set(members)
        assert members["aegis-agent"].mode & 0o111
        assert members["aegis-collector"].mode & 0o111
        assert not members["aegis_exec.bpf.o"].mode & 0o111


def test_required_agent_rejects_missing_kernel_helpers(tmp_path: Path):
    bundle = _bundle_module()
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    (agent_dir / "aegis-agent.exe").write_bytes(b"MZ" + b"\0" * 16)
    (agent_dir / "aegis-agent").write_bytes(b"\x7fELF" + b"\0" * 16)
    with pytest.raises(SystemExit):
        bundle._agent_assets(agent_dir, tmp_path, "v4.3.0", True)


def test_bundle_script_has_no_legacy_assets():
    source = SCRIPT.read_text(encoding="utf-8")
    assert "aegis-guard/target" not in source
    assert "nodetrace.zip" not in source
    assert "aegis-agent-windows-amd64" not in source


def test_smoke_rejects_unified_archive_without_the_agent_binary(tmp_path: Path):
    spec = importlib.util.spec_from_file_location(
        "release_smoke", ROOT / "scripts" / "release-smoke.py"
    )
    assert spec and spec.loader
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    with zipfile.ZipFile(tmp_path / "unified-latest.zip", "w") as zf:
        zf.writestr("README.txt", "not the agent")
    (tmp_path / "unified-4.3.0.zip").write_bytes(
        (tmp_path / "unified-latest.zip").read_bytes())
    linux_agent = tmp_path / "agent-linux"
    linux_agent.write_bytes(b"\x7fELF" + b"\0" * 16)
    with tarfile.open(tmp_path / "unified-latest.tar.gz", "w:gz") as tf:
        tf.add(linux_agent, arcname="aegis-agent")
    (tmp_path / "unified-4.3.0.tar.gz").write_bytes(
        (tmp_path / "unified-latest.tar.gz").read_bytes())

    problems = smoke.check_agent_assets(tmp_path, "v4.3.0")

    assert any("unified-latest.zip" in problem for problem in problems)
