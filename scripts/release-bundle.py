#!/usr/bin/env python3
"""Build a release bundle from reproducible repository artifacts.

This is the local dry-run counterpart of the GitHub `release` job. It does not
create a tag and it does not invent a signature: the tag workflow must sign the
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
    "docs/RELEASE_SIGNING.md",
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


RELEASE_NAMES = {
    ".env.example": "env.example",
}


def release_name(rel: str) -> str:
    """Release asset name for a repository-relative input.

    GitHub rewrites names that start with a dot when uploading release assets;
    `env.example` is the stable name the installer and smoke test use.
    """
    return RELEASE_NAMES.get(rel, Path(rel).name)


def _copy(src: Path, dst: Path) -> None:
    if not src.is_file() or src.stat().st_size == 0:
        raise SystemExit(f"[X] missing or empty release input: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _zip_tree(src: Path, dst: Path, exclude: frozenset[str] = frozenset()) -> None:
    if not src.is_dir():
        raise SystemExit(f"[X] missing release directory: {src}")
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(src.rglob("*")):
            if path.is_file() and path.name not in exclude:
                archive.write(path, path.relative_to(src).as_posix())


def _tar_member(archive: tarfile.TarFile, path: Path, arcname: str,
                mode: int) -> None:
    info = tarfile.TarInfo(arcname)
    info.size = path.stat().st_size
    info.mode = mode
    info.mtime = int(path.stat().st_mtime)
    with path.open("rb") as handle:
        archive.addfile(info, handle)


def _assert_lf_source(archive: Path) -> None:
    """Reject CRLF text in the source archive: the bundle targets Linux.

    `git archive` applies core.eol, so a Windows builder with autocrlf=true
    wrote CRLF into every text file of the tarball even though the blobs are
    LF. The archive is now generated with an explicit LF config; this guard
    fails the build if any text member still contains CR.
    """
    offenders = []
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            handle = tar.extractfile(member)
            data = handle.read() if handle else b""
            if b"\r" not in data or b"\x00" in data:
                continue
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                continue
            offenders.append(member.name)
    if offenders:
        raise SystemExit(
            "[X] source archive ships CRLF text: " + ", ".join(offenders[:5])
        )


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def _agent_assets(agent_dir: Path, out: Path, version: str,
                  required: bool) -> list[str]:
    """Ship only the unified Go agent and its kernel helpers.

    4.3 is the unified-only release: Guard and NodeTrace are not copied into
    the bundle. The four archives are the complete install set:

      * Windows: `aegis-agent.exe` + `aegis-etw.exe`
      * Linux: `aegis-agent` + `aegis-collector` + `aegis_exec.bpf.o`

    The versioned copies make the signed OTA command (`UPDATE_AGENT` with an
    explicit version) resolvable. Raw binaries are deliberately not shipped:
    the installers consume the archives, and two extra copies only create
    ambiguity about which file is the supported one.
    """
    windows = agent_dir / "aegis-agent.exe"
    linux = agent_dir / "aegis-agent"
    etw = agent_dir / "aegis-etw.exe"
    collector = agent_dir / "aegis-collector"
    bpf_obj = agent_dir / "aegis_exec.bpf.o"
    required_files = (windows, linux, etw, collector, bpf_obj)
    present = [path for path in required_files if path.is_file()]
    if not present and not required:
        return []
    if required:
        missing = [path.name for path in required_files if not path.is_file()]
        if missing:
            raise SystemExit(
                "[X] incomplete unified agent directory; missing: "
                + ", ".join(missing)
            )

    created: list[str] = []
    tag = version.lstrip("v")
    if windows.is_file():
        with zipfile.ZipFile(out / "unified-latest.zip", "w",
                             zipfile.ZIP_DEFLATED) as archive:
            archive.write(windows, "aegis-agent.exe")
            if etw.is_file():
                archive.write(etw, "aegis-etw.exe")
        shutil.copy2(out / "unified-latest.zip", out / f"unified-{tag}.zip")
        created += ["unified-latest.zip", f"unified-{tag}.zip"]
    if linux.is_file():
        latest_tar = out / "unified-latest.tar.gz"
        with tarfile.open(latest_tar, "w:gz") as archive:
            _tar_member(archive, linux, "aegis-agent", 0o755)
            if collector.is_file():
                _tar_member(archive, collector, "aegis-collector", 0o755)
            if bpf_obj.is_file():
                _tar_member(archive, bpf_obj, "aegis_exec.bpf.o", 0o644)
        # Build once and copy: separate tarfile runs embed different gzip
        # timestamps, so the versioned OTA copy would not be byte-identical.
        shutil.copy2(latest_tar, out / f"unified-{tag}.tar.gz")
        created += ["unified-latest.tar.gz", f"unified-{tag}.tar.gz"]
    return created


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True, help="release label, e.g. v4.1.0-rc1")
    parser.add_argument("--out", default="release")
    parser.add_argument("--force", action="store_true", help="replace an existing bundle")
    parser.add_argument("--sbom-dir", help="directory with per-image CycloneDX SBOMs")
    parser.add_argument("--agent-dir",
                        help="directory with aegis-agent.exe (Windows) and aegis-agent (Linux)")
    parser.add_argument("--require-agent", action="store_true",
                        help="fail if the unified agent or kernel helpers are absent")
    args = parser.parse_args()
    if not re.fullmatch(r"v?[0-9]+\.[0-9]+\.[0-9]+(?:-rc[0-9]+)?", args.version):
        raise SystemExit("version must be SemVer or vX.Y.Z-rcN")
    if args.require_agent and not args.agent_dir:
        raise SystemExit("[X] --require-agent needs --agent-dir")
    out = (ROOT / args.out).resolve()
    if out.exists():
        if not args.force:
            raise SystemExit(f"[X] {out} already exists; use --force to replace it")
        shutil.rmtree(out)
    out.mkdir(parents=True)

    for rel in CORE_FILES:
        _copy(ROOT / rel, out / release_name(rel))

    frontend = ROOT / "frontend/dist"
    if frontend.is_dir():
        _zip_tree(frontend, out / "frontend.zip")

    agent_files: list[str] = []
    if args.agent_dir:
        agent_dir = (ROOT / args.agent_dir).resolve()
        if not agent_dir.is_dir():
            raise SystemExit(f"[X] Go agent directory missing: {agent_dir}")
        agent_files = _agent_assets(agent_dir, out, args.version, args.require_agent)

    sbom = ROOT / "sbom.cyclonedx.json"
    if not sbom.is_file():
        sbom = ROOT / "sbom.spdx.json"
    if not sbom.is_file():
        raise SystemExit("[X] SBOM missing: supply_chain must generate it before release")
    _copy(sbom, out / "sbom.cyclonedx.json")

    image_sboms = []
    if args.sbom_dir:
        sbom_dir = (ROOT / args.sbom_dir).resolve()
        if not sbom_dir.is_dir():
            raise SystemExit(f"[X] per-image SBOM directory missing: {sbom_dir}")
        sbom_files = sorted(sbom_dir.glob("*.json"))
        if not sbom_files:
            raise SystemExit(f"[X] no per-image SBOMs in {sbom_dir}")
        for sbom_file in sbom_files:
            if sbom_file.name == "sbom.cyclonedx.json":
                raise SystemExit("[X] per-image SBOM collides with repository SBOM")
            _copy(sbom_file, out / sbom_file.name)
            image_sboms.append(sbom_file.name)

    # Preserve the service boundary and the source provenance without shipping
    # the whole working tree (including local secrets and .perch).
    source = out / "aegis-source.tar.gz"
    subprocess.check_call(
        ["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf",
         "archive", "--format=tar.gz", f"--prefix=aegis-{args.version}/",
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

    # Write LF bytes explicitly: Path.write_text() applies the platform newline
    # translation, and a CRLF SHA256SUMS.txt makes `sha256sum -c` fail on Unix
    # and on Git Bash because the file name keeps a trailing '\r'.
    digest_lines = [f"{item['sha256']}  {item['name']}" for item in files]
    (out / "SHA256SUMS.txt").write_bytes(
        ("\n".join(digest_lines) + "\n").encode("utf-8")
    )
    manifest = {
        "version": args.version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git("rev-parse", "HEAD"),
        "git_branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "components": ["aegis-brain", "aegis-link", "frontend",
                       "aegis-agent", "aegis-ebpf", "services/kraken"],
        "files": files,
        "agent_files": agent_files,
        "image_sboms": image_sboms,
        "signature": "not produced; 4.3.0 is unsigned by decision (RELEASE_SIGNING.md)",
    }
    (out / "RELEASE_MANIFEST.json").write_bytes(
        (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    )
    print(f"Release bundle {args.version}: {len(files)} files in {out}")
    for item in files:
        print(f"  {item['sha256']}  {item['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
