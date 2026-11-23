#!/usr/bin/env python3
"""Start/probe a three-node Kraken lab and emit evidence.

This is intentionally a *simulated* multi-host lab: three independent sensor
containers on one Docker engine with distinct ports and health. It validates
fan-out and per-node reachability, not a real network partition or a second
host. The evidence says so explicitly.

    python scripts/kraken_lab_multihost.py --build
    python scripts/kraken_lab_multihost.py --down

Requires Docker Compose and the base Kraken profile secrets in .env.
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB_COMPOSE = ROOT / "deploy/kraken-lab/docker-compose.lab.yml"
NODES = {
    "kraken-lab-node-a": {"ssh": 12222, "http": 18080, "site": "site-a"},
    "kraken-lab-node-b": {"ssh": 12223, "http": 18081, "site": "site-b"},
    "kraken-lab-node-c": {"ssh": 12224, "http": 18082, "site": "site-c"},
}


def compose(*args: str, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    cmd = [
        "docker", "compose",
        "-f", "docker-compose.yml",
        "-f", str(LAB_COMPOSE),
        "--profile", "kraken", "--profile", "kraken-lab",
        *args,
    ]
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True,
                          timeout=timeout, check=False)


def _connect(port: int, payload: bytes | None = None, timeout: float = 5.0) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if payload:
            sock.sendall(payload)
        try:
            return sock.recv(1024)
        except socket.timeout:
            return b""


def wait_nodes(deadline_s: int = 180) -> dict[str, bool]:
    end = time.monotonic() + deadline_s
    while time.monotonic() < end:
        ready = {}
        for service in NODES:
            result = compose("ps", "-q", service, timeout=30)
            ids = [line for line in result.stdout.splitlines() if line.strip()]
            ready[service] = bool(ids)
        if all(ready.values()):
            return ready
        time.sleep(3)
    return {service: False for service in NODES}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--down", action="store_true")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args(argv)
    if not LAB_COMPOSE.is_file():
        print(f"lab compose missing: {LAB_COMPOSE}", file=sys.stderr)
        return 2
    if args.down:
        result = compose("rm", "-sf", *NODES, timeout=120)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            return result.returncode
        print("Kraken lab nodes removed")
        return 0

    up_args = ["up", "-d"]
    if args.build:
        up_args.append("--build")
    up_args.extend(NODES)
    result = compose(*up_args, timeout=max(args.timeout, 600))
    if result.returncode != 0:
        print(result.stderr or result.stdout, file=sys.stderr)
        return result.returncode
    running = wait_nodes(args.timeout)
    if not all(running.values()):
        print("not all lab nodes are running; inspect docker compose ps", file=sys.stderr)
        return 1

    probes: dict[str, dict] = {}
    failures: list[str] = []
    for service, cfg in NODES.items():
        http = b""
        ssh = b""
        try:
            http = _connect(cfg["http"], b"GET / HTTP/1.1\r\nHost: lab.local\r\nConnection: close\r\n\r\n")
        except OSError as exc:
            failures.append(f"{service}: HTTP probe failed: {exc}")
        try:
            ssh = _connect(cfg["ssh"])
        except OSError as exc:
            failures.append(f"{service}: SSH probe failed: {exc}")
        probes[service] = {
            "site": cfg["site"],
            "http_banner": http.decode("latin-1", "replace").splitlines()[0] if http else "",
            "ssh_banner": ssh.decode("latin-1", "replace").strip()[:120],
        }
        if b"200" not in http[:20]:
            failures.append(f"{service}: HTTP did not answer 200")
        if not ssh:
            failures.append(f"{service}: SSH offered no banner")

    evidence = {
        "schema": "aegis-kraken-lab-v1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "topology": "three independent sensor containers",
        "single_host": True,
        "true_multi_host": False,
        "nodes": probes,
        "failures": failures,
        "passed": not failures,
        "limitation": "Docker engine and kernel are shared; network partition and scheduler failover are not tested.",
    }
    out = ROOT / "dist/drills"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"kraken-lab-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": evidence["passed"], "evidence": str(path),
                      "failures": failures}, indent=2))
    if not args.keep:
        compose("rm", "-sf", *NODES, timeout=120)
    return 0 if evidence["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
