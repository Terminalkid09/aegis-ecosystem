"""Release-bundle contract tests.

The release job runs the bundle from a tag checkout, not from a developer
machine. These tests pin the two things that broke in 4.1: the asset name for
the environment template and the exclusion of the agent identity from the
NodeTrace zip.
"""
from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path

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
