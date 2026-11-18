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
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default="release")
    parser.add_argument("--require-nodetrace", action="store_true")
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
    checksums = {}
    for line in checksums_path.read_text(encoding="utf-8").splitlines():
        if "  " in line:
            digest, name = line.split("  ", 1)
            checksums[name] = digest
    for item in manifest.get("files", []):
        if checksums.get(item["name"]) != item["sha256"]:
            print(f"[X] SHA256SUMS mismatch: {item['name']}")
            return 1
    required = ("docker-compose.yml", "docker-compose.prod.yml", "env.example",
                "frontend.zip", "sbom.cyclonedx.json", "aegis-guard.jar",
                "aegis-source.tar.gz", "RELEASE_SIGNING.md")
    if args.require_nodetrace:
        required += ("nodetrace.zip",)
    for name in required:
        if not (root / name).is_file():
            print(f"[X] required release asset missing: {name}")
            return 1
    if args.require_image_sboms and not manifest.get("image_sboms"):
        print("[X] per-image SBOMs missing from RELEASE_MANIFEST.json")
        return 1
    print(f"[OK] release {manifest.get('version')} verified: {len(manifest.get('files', []))} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
