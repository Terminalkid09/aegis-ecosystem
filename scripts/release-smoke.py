#!/usr/bin/env python3
"""Smoke-test a unified-only release directory after download (AP-50).

It verifies the manifest, every checksum, the presence of the compose bundle,
the SBOM and the unified agent archives. It never needs the repository checkout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
import zipfile
from pathlib import Path


FORBIDDEN_LEGACY = (
    "aegis-guard.jar",
    "nodetrace.zip",
    "aegis-guard-latest.zip",
    "aegis-guard-latest.tar.gz",
    "nodetrace-latest.zip",
    "nodetrace-latest.tar.gz",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _archive_members(path: Path) -> dict[str, tarfile.TarInfo]:
    with tarfile.open(path, "r:gz") as archive:
        return {Path(m.name).name: m for m in archive.getmembers() if m.isfile()}


def check_signing_sidecars(root: Path) -> list[str]:
    """Reject test/unsigned packages copied into a release directory.

    The tag bundle normally has no endpoint packages, but an operator may attach
    them. Presence is optional; a present package must carry a production
    sidecar, and a production MSI must have a valid timestamped signature.
    """
    problems: list[str] = []
    for path in sorted(root.glob("*.signing.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            problems.append(f"cannot read signing sidecar {path.name}: {exc}")
            continue
        package = str(data.get("package") or path.name.removesuffix(".signing.json"))
        mode = str(data.get("mode") or "")
        if mode != "production":
            problems.append(f"{package}: signing mode is {mode!r}, expected production")
            continue
        if package.lower().endswith(".msi"):
            if str(data.get("status") or "") != "Valid":
                problems.append(f"{package}: Authenticode status is not Valid")
            if not data.get("timestamp"):
                problems.append(f"{package}: RFC 3161 timestamp is missing")
    return problems


def check_agent_assets(root: Path, version: str) -> list[str]:
    """Validate the complete unified artifact without running it.

    A release that claims to ship the unified agent must contain both platforms,
    the versioned OTA copies and the kernel helpers used by the Go consumer.
    Checking archive contents and executable modes catches an empty/wrong file
    that a checksum alone would happily accept.
    """
    problems: list[str] = []
    tag = version.lstrip("v")
    for name in FORBIDDEN_LEGACY:
        if (root / name).exists():
            problems.append(f"{name} is legacy and must not be in a unified-only bundle")
    for name in ("aegis-agent-windows-amd64.exe", "aegis-agent-linux-amd64"):
        if (root / name).exists():
            problems.append(f"{name} is a raw binary; ship only the unified archives")

    windows_archives = (root / "unified-latest.zip", root / f"unified-{tag}.zip")
    linux_archives = (root / "unified-latest.tar.gz", root / f"unified-{tag}.tar.gz")
    for path in (*windows_archives, *linux_archives):
        if not path.is_file():
            problems.append(f"missing required unified archive: {path.name}")
    if windows_archives[0].is_file() and windows_archives[1].is_file():
        if sha256(windows_archives[0]) != sha256(windows_archives[1]):
            problems.append("unified-latest.zip and the versioned copy differ")
    if linux_archives[0].is_file() and linux_archives[1].is_file():
        if sha256(linux_archives[0]) != sha256(linux_archives[1]):
            problems.append("unified-latest.tar.gz and the versioned copy differ")

    zip_path = windows_archives[0]
    if zip_path.is_file():
        try:
            with zipfile.ZipFile(zip_path) as archive:
                names = {Path(name).name for name in archive.namelist()}
            if "aegis-agent.exe" not in names:
                problems.append("unified-latest.zip does not contain aegis-agent.exe")
            if "aegis-etw.exe" not in names:
                problems.append("unified-latest.zip does not contain aegis-etw.exe")
        except zipfile.BadZipFile:
            problems.append("unified-latest.zip is not a valid zip archive")

    tar_path = linux_archives[0]
    if tar_path.is_file():
        try:
            members = _archive_members(tar_path)
            for name in ("aegis-agent", "aegis-collector", "aegis_exec.bpf.o"):
                if name not in members:
                    problems.append(f"unified-latest.tar.gz does not contain {name}")
            if "aegis-agent" in members and not members["aegis-agent"].mode & 0o111:
                problems.append("unified-latest.tar.gz aegis-agent is not executable")
            if "aegis-collector" in members and not members["aegis-collector"].mode & 0o111:
                problems.append("unified-latest.tar.gz aegis-collector is not executable")
        except tarfile.TarError:
            problems.append("unified-latest.tar.gz is not a valid tar.gz archive")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default="release")
    parser.add_argument("--require-agent", action="store_true",
                        help="require both unified archives, OTA copies and kernel helpers")
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
                "frontend.zip", "sbom.cyclonedx.json",
                "aegis-source.tar.gz", "RELEASE_SIGNING.md")
    version = str(manifest.get("version") or "")
    if args.require_agent:
        if not version:
            print("[X] RELEASE_MANIFEST.json has no version")
            return 1
        tag = version.lstrip("v")
        required += ("unified-latest.zip", "unified-latest.tar.gz",
                     f"unified-{tag}.zip", f"unified-{tag}.tar.gz")
    for name in required:
        if not (root / name).is_file():
            print(f"[X] required release asset missing: {name}")
            return 1
    if args.require_agent:
        problems = check_agent_assets(root, version)
        if problems:
            for problem in problems:
                print(f"[X] {problem}")
            return 1
    if args.require_image_sboms and not manifest.get("image_sboms"):
        print("[X] per-image SBOMs missing from RELEASE_MANIFEST.json")
        return 1
    signing_problems = check_signing_sidecars(root)
    if signing_problems:
        for problem in signing_problems:
            print(f"[X] {problem}")
        return 1
    print(f"[OK] release {manifest.get('version')} verified: {len(manifest.get('files', []))} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
