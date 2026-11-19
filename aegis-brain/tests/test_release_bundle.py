"""Release-bundle contract tests.

The release job runs the bundle from a tag checkout, not from a developer
machine. These tests pin the two things that broke in 4.1: the asset name for
the environment template and the exclusion of the agent identity from the
NodeTrace zip.
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


def test_nodetrace_zip_excludes_local_device_identity(tmp_path: Path):
    bundle = _bundle_module()
    source = tmp_path / "dist"
    source.mkdir()
    (source / "nodetrace-agent.exe").write_text("binary", encoding="utf-8")
    (source / "config.json").write_text("{}", encoding="utf-8")
    for name in bundle.NODETRACE_IDENTITY_FILES:
        (source / name).write_text("must-not-ship", encoding="utf-8")

    archive = tmp_path / "nodetrace.zip"
    bundle._zip_tree(source, archive, exclude=bundle.NODETRACE_IDENTITY_FILES)

    with zipfile.ZipFile(archive) as zf:
        names = {Path(name).name for name in zf.namelist()}

    assert "nodetrace-agent.exe" in names
    assert "config.json" in names
    assert names.isdisjoint(bundle.NODETRACE_IDENTITY_FILES)


def test_agent_assets_ship_both_platforms_and_unified_archives(tmp_path: Path):
    bundle = _bundle_module()
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    (agent_dir / "aegis-agent.exe").write_bytes(b"MZ" + b"\0" * 16)
    (agent_dir / "aegis-agent").write_bytes(b"\x7fELF" + b"\0" * 16)
    out = tmp_path / "release"
    out.mkdir()

    created = bundle._agent_assets(agent_dir, out, "v4.3.0", True)

    assert set(created) == {
        "aegis-agent-windows-amd64.exe", "aegis-agent-linux-amd64",
        "unified-latest.zip", "unified-4.3.0.zip",
        "unified-latest.tar.gz", "unified-4.3.0.tar.gz",
    }
    with zipfile.ZipFile(out / "unified-latest.zip") as zf:
        assert "aegis-agent.exe" in zf.namelist()
    with tarfile.open(out / "unified-latest.tar.gz") as tf:
        member = tf.getmember("aegis-agent")
        assert member.mode & 0o111


def test_required_agent_fails_when_a_platform_is_missing(tmp_path: Path):
    bundle = _bundle_module()
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    (agent_dir / "aegis-agent.exe").write_bytes(b"MZ" + b"\0" * 16)
    with pytest.raises(SystemExit):
        bundle._agent_assets(agent_dir, tmp_path, "v4.3.0", True)


def test_smoke_rejects_unified_archive_without_the_agent_binary(tmp_path: Path):
    spec = importlib.util.spec_from_file_location(
        "release_smoke", ROOT / "scripts" / "release-smoke.py"
    )
    assert spec and spec.loader
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)
    (tmp_path / "aegis-agent-windows-amd64.exe").write_bytes(b"MZ" + b"\0" * 16)
    (tmp_path / "aegis-agent-linux-amd64").write_bytes(b"\x7fELF" + b"\0" * 16)
    with zipfile.ZipFile(tmp_path / "unified-latest.zip", "w") as zf:
        zf.writestr("README.txt", "not the agent")
    with tarfile.open(tmp_path / "unified-latest.tar.gz", "w:gz") as tf:
        tf.add(tmp_path / "aegis-agent-linux-amd64", arcname="aegis-agent")

    problems = smoke.check_agent_assets(tmp_path)

    assert any("unified-latest.zip" in problem for problem in problems)
