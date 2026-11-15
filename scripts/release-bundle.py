#!/usr/bin/env python3
"""Build a release bundle from reproducible repository artifacts.

This is the local dry-run counterpart of the GitHub `release` job. It does not
create a tag and it does not invent a signature: the workflow signs the
resulting SHA256SUMS with cosign, while this script verifies every file and
writes the manifest a client can check after download.

Usage:
    python scripts/release-bundle.py --version v4.1.0-rc1 --out release
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORE_FILES = [
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "docker-compose.mtls.yml",
    "docker-compose.ha.yml",
    "Caddyfile",
    "Caddyfile.mtls",
    ".env.example",
    "install.sh",
    "install.ps1",
    "CHANGELOG.md",
    "UPGRADING.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "TRADEMARK.md",
    "README.md",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy(src: Path, dst: Path) -> None:
    if not src.is_file() or src.stat().st_size == 0:
        raise SystemExit(f"[X] missing or empty release input: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _zip_tree(src: Path, dst: Path) -> None:
    if not src.is_dir():
        raise SystemExit(f"[X] missing release directory: {src}")
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(src.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(src).as_posix())


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, help="release label, e.g. v4.1.0-rc1")
    parser.add_argument("--out", default="release")
    parser.add_argument("--force", action="store_true", help="replace an existing bundle")
    args = parser.parse_args()
    if not re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?", args.version):
        raise SystemExit("version must be SemVer or vX.Y.Z-rcN")
    out = (ROOT / args.out).resolve()
    if out.exists():
        if not args.force:
            raise SystemExit(f"[X] {out} already exists; use --force to replace it")
        shutil.rmtree(out)
    out.mkdir(parents=True)

    for rel in CORE_FILES:
        _copy(ROOT / rel, out / Path(rel).name)

    _copy(ROOT / "aegis-guard/target/aegis-guard.jar", out / "aegis-guard.jar")

    nt = ROOT / "NodeTrace/agents/python/dist/nodetrace-agent"
    if nt.is_dir():
        _zip_tree(nt, out / "nodetrace.zip")
    frontend = ROOT / "frontend/dist"
    if frontend.is_dir():
        _zip_tree(frontend, out / "frontend.zip")

    sbom = ROOT / "sbom.cyclonedx.json"
    if not sbom.is_file():
        sbom = ROOT / "sbom.spdx.json"
    if not sbom.is_file():
        raise SystemExit("[X] SBOM missing: supply_chain must generate it before release")
    _copy(sbom, out / "sbom.cyclonedx.json")

    # Preserve the service boundary and the source provenance without shipping
    # the whole working tree (including local secrets and .perch).
    source = out / "aegis-source.tar.gz"
    subprocess.check_call(
        ["git", "archive", "--format=tar.gz", f"--prefix=aegis-{args.version}/",
         "-o", str(source), "HEAD"],
        cwd=ROOT,
    )
    if source.stat().st_size == 0:
        raise SystemExit("[X] git archive produced an empty source bundle")

    files = []
    for path in sorted(out.rglob("*")):
        if path.is_file() and path.name not in {"SHA256SUMS.txt", "RELEASE_MANIFEST.json"}:
            files.append({"name": path.relative_to(out).as_posix(),
                          "bytes": path.stat().st_size,
                          "sha256": _sha256(path)})
    if not files:
        raise SystemExit("[X] release bundle is empty")

    digest_lines = [f"{item['sha256']}  {item['name']}" for item in files]
    (out / "SHA256SUMS.txt").write_text("\n".join(digest_lines) + "\n", encoding="utf-8")
    manifest = {
        "version": args.version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git("rev-parse", "HEAD"),
        "git_branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "components": ["aegis-brain", "aegis-guard", "aegis-link", "frontend",
                       "NodeTrace", "services/kraken"],
        "files": files,
        "signature": "cosign signs SHA256SUMS.txt in the GitHub release job",
    }
    (out / "RELEASE_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Release bundle {args.version}: {len(files)} files in {out}")
    for item in files:
        print(f"  {item['sha256']}  {item['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
