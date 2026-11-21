#!/usr/bin/env python3
"""Verify that Docker resource limits are configurable, not hard-coded.

The check uses `docker compose config` with explicit overlay files.  It does
not start containers and never prints secrets.  CI runs it as a cheap guard
against a future edit that silently removes an environment override.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

DUMMY_ENV = {
    "POSTGRES_PASSWORD": "ci-dummy",
    "DATABASE_URL": "postgresql+asyncpg://ci:ci@localhost:5432/ci",
    "SHODAN_API_KEY": "ci-dummy",
    "ABUSEIPDB_API_KEY": "ci-dummy",
    "REDIS_PASSWORD": "ci-dummy",
    "AEGIS_API_KEY": "ci-dummy-api-key",
    "AGENT_ENROLL_KEY": "ci-dummy-enroll-key",
    "JWT_SECRET": "ci-dummy-jwt-secret-32-chars-min",
    "MASTER_KEY_B64": "Q/wCZ5reU82bQpZppUc6Qq80sybBPz4Q276NbMBF97Q=",
    "KRAKEN_DB_PASSWORD": "ci-dummy-kraken-db-password",
    "KRAKEN_REDIS_PASSWORD": "ci-dummy-kraken-redis-password",
    "KRAKEN_SECRET_KEY": "ci-dummy-kraken-secret-key-32-chars-min",
    "KRAKEN_INTERNAL_API_KEY": "ci-dummy-kraken-internal-key-32-chars-min",
    "KRAKEN_SSO_SECRET": "ci-dummy-kraken-sso-secret-32-chars-min",
    "SANDBOX_BROKER_TOKEN": "ci-dummy-sandbox-broker-token-32-chars-min",
    "KRAKEN_SENSOR_PROTOCOLS": "ssh,http,ftp,telnet,smb,rdp",
    "AEGIS_BRAIN_MEM_LIMIT": "750m",
    "AEGIS_BRAIN_CPUS": "0.75",
    "AEGIS_BRAIN_PIDS": "321",
    "AEGIS_KRAKEN_SENSORS_MEM_LIMIT": "384m",
    "AEGIS_KRAKEN_SENSORS_CPUS": "0.40",
    "AEGIS_KRAKEN_SENSORS_PIDS": "180",
    "AEGIS_KRAKEN_RDP_MEM_LIMIT": "896m",
    "AEGIS_KRAKEN_RDP_CPUS": "0.80",
    "AEGIS_KRAKEN_RDP_PIDS": "240",
}


def _config() -> dict:
    env = os.environ.copy()
    env.update(DUMMY_ENV)
    command = [
        "docker", "compose",
        "--profile", "kraken",
        "-f", os.path.join(ROOT, "docker-compose.yml"),
        "-f", os.path.join(ROOT, "docker-compose.kraken-honeypot.yml"),
        "config", "--format", "json",
    ]
    result = subprocess.run(
        command, cwd=ROOT, env=env, text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        print(result.stderr.strip() or result.stdout.strip(), file=sys.stderr)
        raise SystemExit(f"docker compose config failed (exit {result.returncode})")
    return json.loads(result.stdout)


def _mem_bytes(value) -> int:
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    units = {"k": 1000, "m": 1000**2, "g": 1000**3}
    if text[-1:] in units:
        return int(float(text[:-1]) * units[text[-1]])
    return int(float(text))


def main() -> int:
    services = _config()["services"]
    expected = {
        "aegis-brain": (786_432_000, 0.75, 321),
        "aegis-kraken-sensors": (402_653_184, 0.40, 180),
        "aegis-kraken-rdp": (939_524_096, 0.80, 240),
    }
    failures = []
    for name, (mem, cpus, pids) in expected.items():
        service = services.get(name)
        if service is None:
            failures.append(f"{name}: missing from compose config")
            continue
        actual_mem = _mem_bytes(service.get("mem_limit", 0))
        actual_cpus = float(service.get("cpus", 0) or 0)
        actual_pids = int(service.get("pids_limit", 0) or 0)
        if actual_mem != mem or abs(actual_cpus - cpus) > 0.001 or actual_pids != pids:
            failures.append(
                f"{name}: expected mem={mem} cpus={cpus} pids={pids}; "
                f"got mem={actual_mem} cpus={actual_cpus} pids={actual_pids}"
            )
    rdp_ports = services.get("aegis-kraken-rdp", {}).get("ports") or []
    if not any(str(port.get("target")) == "3389" for port in rdp_ports):
        failures.append("aegis-kraken-rdp: port 3389 is not published by the overlay")
    if failures:
        print("compose limits check FAILED", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("compose limits check PASS (env overrides + RDP overlay port)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
