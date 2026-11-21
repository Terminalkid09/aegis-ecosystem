#!/usr/bin/env python3
"""Exercise the Kraken sandbox isolation policy without executing malware.

This is an infrastructure test, not a detonation test: it uses a harmless text
sample to prove that the same policy used by the broker (network=none,
read-only root, cap-drop ALL, no-new-privileges, bounded pids/memory, tmpfs)
runs, cannot reach the network, and can be killed. A real detonation worker
must be supplied separately with an authorized sample and its own lab.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KRAKEN = ROOT / "services" / "kraken"
DOCKERFILE = KRAKEN / "Dockerfile.sandbox"


def run(command: list[str], check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        command, check=check, timeout=timeout, text=True, capture_output=True
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="kraken-sandbox-isolation:test")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()
    if not DOCKERFILE.is_file():
        print(f"[X] sandbox Dockerfile missing: {DOCKERFILE}", file=sys.stderr)
        return 1
    if shutil.which("docker") is None:
        print("[X] docker is required for the isolation test", file=sys.stderr)
        return 1
    if not args.skip_build:
        build = run(
            ["docker", "build", "-f", str(DOCKERFILE), "-t", args.image, str(KRAKEN)],
            check=False,
            timeout=300,
        )
        if build.returncode != 0:
            print(build.stderr[-2000:], file=sys.stderr)
            return 1

    name = f"kraken-isolation-{uuid.uuid4().hex[:8]}"
    common = [
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "64",
        "--memory",
        "128m",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=16m",
    ]
    try:
        with tempfile.TemporaryDirectory(prefix="aegis-isolation-") as tmp:
            sample = Path(tmp) / "sample.txt"
            sample.write_text("harmless isolation probe\n", encoding="utf-8")
            read = run(
                [
                    "docker", "run", *common,
                    "-v", f"{sample}:/sample/sample.txt:ro",
                    "--entrypoint", "/bin/sh", args.image,
                    "-c", "cat /sample/sample.txt >/dev/null && echo read-ok",
                ],
                check=False,
            )
            if read.returncode != 0 or "read-ok" not in read.stdout:
                print(f"[X] sandbox read test failed: {read.stderr[-1000:]}", file=sys.stderr)
                return 1

            network = run(
                [
                    "docker", "run", *common,
                    "--entrypoint", "/bin/sh", args.image,
                    "-c", "curl -fsS --max-time 2 http://1.1.1.1 >/dev/null",
                ],
                check=False,
            )
            if network.returncode == 0:
                print("[X] sandbox reached the network despite network=none", file=sys.stderr)
                return 1

            run(
                [
                    "docker", "run", "-d", "--name", name,
                    *common,
                    "--entrypoint", "/bin/sh", args.image,
                    "-c", "sleep 60",
                ],
                check=True,
            )
            killed = run(["docker", "kill", name], check=False)
            if killed.returncode != 0:
                print(f"[X] kill switch failed: {killed.stderr[-1000:]}", file=sys.stderr)
                return 1
            running = run(
                ["docker", "inspect", "-f", "{{.State.Running}}", name],
                check=False,
            )
            if running.returncode == 0 and running.stdout.strip() == "true":
                print("[X] container is still running after kill", file=sys.stderr)
                return 1
            print("sandbox isolation PASS (read-only, no network, bounded, kill switch)")
            return 0
    finally:
        run(["docker", "rm", "-f", name], check=False)


if __name__ == "__main__":
    raise SystemExit(main())
