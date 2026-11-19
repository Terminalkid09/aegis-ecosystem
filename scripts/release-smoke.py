#!/usr/bin/env python3
"""Smoke-test a release directory after download (AP-50 acceptance).

It verifies the manifest, every checksum, the presence of the compose bundle
and the SBOM. It never needs the repository checkout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
import zipfile
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _binary_magic(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read(4)


def check_agent_assets(root: Path) -> list[str]:
    """Validate the 4.3 Go agent without running it.

    A release that claims to ship the unified agent must contain both platforms
    and the archives the one-liner installers fetch. Checking the archive
    contents and the executable magic catches an empty/wrong file that a
    checksum alone would happily accept.
    """
    problems: list[str] = []
    for name, magic in (("aegis-agent-windows-amd64.exe", b"MZ"),
                        ("aegis-agent-linux-amd64", b"\x7fELF")):
        path = root / name
        if path.is_file() and _binary_magic(path) != magic:
            problems.append(f"{name} is not a {magic!r} executable")

    zip_path = root / "unified-latest.zip"
    if zip_path.is_file():
        try:
            with zipfile.ZipFile(zip_path) as archive:
                names = {Path(name).name for name in archive.namelist()}
            if "aegis-agent.exe" not in names:
                problems.append("unified-latest.zip does not contain aegis-agent.exe")
        except zipfile.BadZipFile:
            problems.append("unified-latest.zip is not a valid zip archive")

    tar_path = root / "unified-latest.tar.gz"
    if tar_path.is_file():
        try:
            with tarfile.open(tar_path, "r:gz") as archive:
                members = {Path(m.name).name: m for m in archive.getmembers()
                           if m.isfile()}
            if "aegis-agent" not in members:
                problems.append("unified-latest.tar.gz does not contain aegis-agent")
            elif not members["aegis-agent"].mode & 0o111:
                problems.append("unified-latest.tar.gz aegis-agent is not executable")
        except tarfile.TarError:
            problems.append("unified-latest.tar.gz is not a valid tar.gz archive")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default="release")
    parser.add_argument("--require-nodetrace", action="store_true")
    parser.add_argument("--require-agent", action="store_true",
                        help="require the Go agent binaries and unified archives")
    parser.add_argument("--require-image-sboms", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    manifest_path = root / "RELEASE_MANIFEST.json"
    checksums_path = root / "SHA256SUMS.txt"
    if not manifest_path.is_file() or not checksums_path.is_file():
        print("[X] manifest or SHA256SUMS.txt missing")
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for item in manifest.get("files", []):
        path = root / item["name"]
        if not path.is_file():
            print(f"[X] missing {item['name']}")
            return 1
        actual = sha256(path)
        if actual != item["sha256"]:
            print(f"[X] checksum mismatch: {item['name']}")
            return 1
    # Check the raw bytes first: splitlines() hides CRLF, and a CRLF checksum
    # file makes `sha256sum -c` fail because each name keeps a trailing '\r'.
    raw_checksums = checksums_path.read_bytes()
    if b"\r" in raw_checksums:
        print("[X] SHA256SUMS.txt contains CR; release checksums must be LF-only")
        return 1
    try:
        checksum_text = raw_checksums.decode("utf-8")
    except UnicodeDecodeError:
        print("[X] SHA256SUMS.txt is not valid UTF-8")
        return 1
    checksums: dict[str, str] = {}
    for lineno, line in enumerate(checksum_text.split("\n"), 1):
        if not line:
            continue
        if "  " not in line:
            print(f"[X] malformed SHA256SUMS.txt line {lineno}: {line!r}")
            return 1
        digest, name = line.split("  ", 1)
        if name in checksums:
            print(f"[X] duplicate checksum entry: {name}")
            return 1
        checksums[name] = digest
    manifest_names = {item["name"] for item in manifest.get("files", [])}
    missing = sorted(manifest_names - set(checksums))
    extra = sorted(set(checksums) - manifest_names)
    if missing or extra:
        if missing:
            print(f"[X] SHA256SUMS.txt missing: {', '.join(missing)}")
        if extra:
            print(f"[X] SHA256SUMS.txt has unexpected entries: {', '.join(extra)}")
        return 1
    for item in manifest.get("files", []):
        if checksums.get(item["name"]) != item["sha256"]:
            print(f"[X] SHA256SUMS mismatch: {item['name']}")
            return 1
    required = ("docker-compose.yml", "docker-compose.prod.yml", "env.example",
                "frontend.zip", "sbom.cyclonedx.json", "aegis-guard.jar",
                "aegis-source.tar.gz", "RELEASE_SIGNING.md")
    if args.require_nodetrace:
        required += ("nodetrace.zip",)
    if args.require_agent:
        required += ("aegis-agent-windows-amd64.exe", "aegis-agent-linux-amd64",
                     "unified-latest.zip", "unified-latest.tar.gz")
    for name in required:
        if not (root / name).is_file():
            print(f"[X] required release asset missing: {name}")
            return 1
    if args.require_agent:
        problems = check_agent_assets(root)
        if problems:
            for problem in problems:
                print(f"[X] {problem}")
            return 1
    if args.require_image_sboms and not manifest.get("image_sboms"):
        print("[X] per-image SBOMs missing from RELEASE_MANIFEST.json")
        return 1
    print(f"[OK] release {manifest.get('version')} verified: {len(manifest.get('files', []))} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
