#!/usr/bin/env python3
"""Contract test for the release bundle assembly.

The tag workflow builds the bundle, then creates the image archive with
`docker save` and adds it to the checksums. The 4.3.0 tag proved that the
release job is only exercised on tags: the archive was added to
SHA256SUMS.txt alone, `release-smoke.py` refused the bundle because the
manifest did not describe that entry, and every pull request stayed green.
This test reproduces the sequence locally so the contract is checked on
every push.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
REQUIRED = (
    "docker-compose.yml",
    "docker-compose.prod.yml",
    "env.example",
    "frontend.zip",
    "sbom.cyclonedx.json",
    "aegis-source.tar.gz",
    "RELEASE_SIGNING.md",
)
ARCHIVE = "aegis-images.tar.gz"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_bundle(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name in REQUIRED:
        (out / name).write_bytes(f"{name}\n".encode("utf-8"))
    files = [
        {"name": name, "bytes": (out / name).stat().st_size,
         "sha256": sha256(out / name)}
        for name in REQUIRED
    ]
    manifest = {"version": "v9.9.9", "files": files, "image_sboms": ["sbom-brain.cyclonedx.json"]}
    (out / "RELEASE_MANIFEST.json").write_bytes(
        (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    )
    (out / "SHA256SUMS.txt").write_bytes(
        ("\n".join(f"{item['sha256']}  {item['name']}" for item in files) + "\n")
        .encode("utf-8")
    )


def run(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), *args],
        capture_output=True, text=True,
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "release"
        build_bundle(out)

        baseline = run("release-smoke.py", str(out))
        if baseline.returncode != 0:
            print("[X] baseline bundle does not pass the smoke test:")
            print(baseline.stdout + baseline.stderr)
            return 1

        (out / ARCHIVE).write_bytes(b"fake docker save archive\n")
        append = run("release-bundle.py", "--out", str(out),
                     "--append-archive", f"{ARCHIVE}*")
        if append.returncode != 0:
            print("[X] appending the image archive failed:")
            print(append.stdout + append.stderr)
            return 1

        closed = run("release-smoke.py", str(out))
        if closed.returncode != 0:
            print("[X] the smoke test refuses a bundle with an appended archive "
                  "(the 4.3.0 tag failure):")
            print(closed.stdout + closed.stderr)
            return 1

        manifest = json.loads((out / "RELEASE_MANIFEST.json").read_text(encoding="utf-8"))
        names = [item["name"] for item in manifest["files"]]
        if ARCHIVE not in names:
            print(f"[X] {ARCHIVE} is missing from RELEASE_MANIFEST.json")
            return 1
        checksums = (out / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
        if len(checksums) != len(names):
            print("[X] SHA256SUMS.txt and RELEASE_MANIFEST.json disagree")
            return 1

        # The guard must still bite: a checksum with no manifest entry is a
        # broken bundle, not a warning.
        (out / "stray.bin").write_bytes(b"not described by the manifest\n")
        with (out / "SHA256SUMS.txt").open("a", encoding="utf-8") as handle:
            handle.write(f"{sha256(out / 'stray.bin')}  stray.bin\n")
        stray = run("release-smoke.py", str(out))
        if stray.returncode == 0:
            print("[X] the smoke test accepted a checksum with no manifest entry")
            return 1

    print("[OK] release bundle contract: manifest, checksums and smoke test agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
