#!/usr/bin/env python3
"""Validate every supported compose overlay as a real Compose project.

`docker compose config` resolves the merged project (base file plus overlay) and
rejects keys that cannot be combined, such as the legacy service-level `cpus`
alongside `deploy.resources.limits.cpus`. The limits checker only covers the base
file and the honeypot overlay, so a broken HA overlay shipped undetected: this
script runs the check for every overlay in the repository.

The command needs no Docker daemon, only the Compose CLI. Required variables are
discovered from the error output and filled with throw-away values, because the
files are written to fail closed when a secret is missing; the values never leave
this process.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = "docker-compose.yml"
OVERLAYS = [
    "docker-compose.prod.yml",
    "docker-compose.ha.yml",
    "docker-compose.mtls.yml",
    "docker-compose.observability.yml",
    "docker-compose.kraken-honeypot.yml",
]
MISSING = re.compile(r"required variable (\w+) is missing")
MAX_VARS = 30


def compose_config(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args, "config", "-q"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


def validate(overlay: str, base_env: dict[str, str]) -> str | None:
    # Passing the base file twice duplicates every merged list, so the base-only
    # case must not add it a second time.
    args = ["-f", BASE] if overlay == BASE else ["-f", BASE, "-f", overlay]
    env = dict(base_env)
    for _ in range(MAX_VARS):
        result = compose_config(args, env)
        if result.returncode == 0:
            return None
        match = MISSING.search(result.stderr)
        if match is None:
            lines = [line for line in result.stderr.splitlines() if "level=warning" not in line]
            return " ".join(lines).strip() or "docker compose config failed"
        env[match.group(1)] = "compose-overlay-check"
    return "too many required variables; refusing to guess"


def main() -> int:
    base_env = dict(os.environ)
    base_env.setdefault("COMPOSE_PROJECT_NAME", "aegis-overlay-check")
    failures = 0

    error = validate(BASE, base_env)
    if error:
        failures += 1
        print(f"FAIL {BASE}: {error}")
    else:
        print(f"OK   {BASE}")

    for overlay in OVERLAYS:
        error = validate(overlay, base_env)
        if error:
            failures += 1
            print(f"FAIL {overlay}: {error}")
        else:
            print(f"OK   {BASE} + {overlay}")

    if failures:
        print(f"\n{failures} compose project(s) invalid")
        return 1
    print("\ncompose overlay check PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
