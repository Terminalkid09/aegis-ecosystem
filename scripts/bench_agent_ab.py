#!/usr/bin/env python3
"""Live A/B harness for the 4.3 agent cutovers.

This deliberately uses a fake Brain on localhost: it measures process
footprint/startup and event delivery, not PostgreSQL ingest. It never claims to
be a Brain capacity benchmark. Each agent gets its own temp home and a
pre-seeded identity, so registration and certificate bootstrap do not dominate
the sample.

Examples:
    python scripts/bench_agent_ab.py --runs 3 --duration 8
    python scripts/bench_agent_ab.py --only go-sensor,go-endpoint
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

try:
    import psutil
except ImportError as exc:  # pragma: no cover
    raise SystemExit("psutil richiesto: pip install psutil") from exc

ROOT = Path(__file__).resolve().parent.parent
GO = ROOT / "aegis-agent"
GO_BINARY = ROOT / "aegis-agent" / "aegis-agent-bench.exe"
JAVA_JAR = ROOT / "aegis-guard" / "target" / "aegis-guard.jar"
JAVA_HOME = Path(r"C:\Program Files\Eclipse Adoptium\jdk-25.0.5.8-hotspot")
PY_AGENT = ROOT / "NodeTrace" / "agents" / "python" / "agent.py"
PY_BUNDLE = ROOT / "NodeTrace" / "agents" / "python" / "dist" / "nodetrace-agent"
OUT = ROOT / "docs" / "benchmarks" / "4.3"


class Brain(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    counts: dict[str, int] = {}
    lock = threading.Lock()

    def log_message(self, *args):
        return

    def _count(self, path):
        with self.lock:
            self.counts[path] = self.counts.get(path, 0) + 1

    def do_GET(self):
        self._count(self.path)
        body = b"[]"
        if self.path.endswith("/commands/batch") or self.path.endswith("/commands"):
            body = b"[]"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        self._count(self.path)
        length = int(self.headers.get("Content-Length", "0") or 0)
        _ = self.rfile.read(length)
        body = b'{"status":"ok"}'
        if self.path.endswith("/register"):
            body = b'{"device_id":"py-device","device_token":"py-token","status":"registered"}'
        elif self.path.endswith("/enroll/enroll"):
            body = b'{"agent_id":"java-agent","agent_secret":"java-secret"}'
        elif self.path.endswith("/enroll/csr"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.endswith("/batch"):
            body = b'{"status":"ok"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class QuietBrainServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        # Agents are terminated between samples; Windows reports the closed
        # sockets as ConnectionReset. That is expected teardown, not a failure.
        return


def start_brain():
    server = QuietBrainServer(("127.0.0.1", 0), Brain)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def go_env(home: Path, base: str, profile: str) -> dict:
    env = os.environ.copy()
    env.update({
        "AEGIS_AGENT_PROFILE": profile,
        "AEGIS_AGENT_HOME": str(home),
        "AEGIS_IDENTITY_DIR": str(home),
        "AEGIS_SECRET_FILE": str(home / "secret.json"),
        "AEGIS_BRAIN_URL": base + "/api/v1",
        "NODETRACE_IDENTITY_DIR": str(home),
        "NODETRACE_TOKEN_FILE": str(home / "token.json"),
        "NODETRACE_HEARTBEAT_URL": base + "/api/v1/heartbeat",
        "NODETRACE_REGISTER_URL": base + "/api/v1/register",
        "NODETRACE_UPDATE_URL": base + "/api/v1/update",
        "NODETRACE_DEVICE_NAME": "bench-go-" + profile,
        "AEGIS_AGENT_VERSION": "4.3.0-bench",
    })
    return env


def prepare_go(home: Path, base: str, profile: str):
    if profile == "endpoint":
        write_json(home / "secret.json", {
            "agent_id": "go-endpoint", "agent_secret": "go-endpoint-secret",
            "server_url": base + "/api/v1",
        })
    else:
        write_json(home / "token.json", {
            "token": "go-sensor-token", "device_id": "go-sensor",
            # The sensor pins the enrollment URL, not the heartbeat URL.
            "server_url": base + "/api/v1/register",
        })


def prepare_python(home: Path, base: str):
    write_json(home / "config.json", {
        "device_name": "bench-python", "register_url": base + "/api/v1/register",
        "update_url": base + "/api/v1/update", "heartbeat_url": base + "/api/v1/heartbeat",
        "telemetry_interval_seconds": 1, "heartbeat_interval_seconds": 1,
        "retry_max_attempts": 1, "retry_base_delay": 0.1,
    })
    write_json(home / "token.json", {
        "token": "py-token", "device_id": "py-device",
        "server_url": base + "/api/v1/heartbeat",
    })


def prepare_java(home: Path, base: str):
    write_json(home / "secret.json", {
        "agent_id": "java-agent", "agent_secret": "java-secret",
        "server_url": base + "/api/v1",
    })
    (home / "bin").mkdir(exist_ok=True)


def command_for(name: str, home: Path, base: str):
    if name == "go-sensor":
        return [str(GO_BINARY), "--profile", "sensor", "--home", str(home)], str(home), go_env(home, base, "sensor")
    if name == "go-endpoint":
        return [str(GO_BINARY), "--profile", "endpoint", "--home", str(home)], str(home), go_env(home, base, "endpoint")
    if name == "python":
        env = os.environ.copy()
        env.update({
            "NODETRACE_IDENTITY_DIR": str(home), "NODETRACE_TOKEN_FILE": str(home / "token.json"),
            "NODETRACE_DEVICE_NAME": "bench-python",
            "NODETRACE_REGISTER_URL": base + "/api/v1/register",
            "NODETRACE_UPDATE_URL": base + "/api/v1/update",
            "NODETRACE_HEARTBEAT_URL": base + "/api/v1/heartbeat",
            "AEGIS_ENROLL_KEY": "bench-enroll",
        })
        return [sys.executable, str(PY_AGENT)], str(home), env
    if name == "java":
        env = os.environ.copy()
        env.update({
            "AEGIS_AGENT_ID": "java-agent", "AEGIS_AGENT_VERSION": "4.2.1",
            "AEGIS_BRAIN_URL": base + "/api/v1",
            "AEGIS_GATEWAY_URL": base + "/api/v1/telemetry/report",
            "AEGIS_SECRET_FILE": str(home / "secret.json"),
            "AEGIS_IDENTITY_DIR": str(home),
            "AEGIS_ETW_ENABLED": "false",
            "AEGIS_SCAN_INTERVAL_MS": "1000",
            "AEGIS_NETSTAT_INTERVAL_MS": "5000",
        })
        java = JAVA_HOME / "bin" / "java.exe"
        return [str(java), "-jar", str(JAVA_JAR)], str(home), env
    raise ValueError(name)


def sample(name: str, home: Path, base: str, duration: float):
    cmd, cwd, env = command_for(name, home, base)
    start = time.perf_counter()
    proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    rss = []
    cpu = []
    alive_at = None
    try:
        p = psutil.Process(proc.pid)
        deadline = time.time() + duration
        while time.time() < deadline:
            time.sleep(0.75)
            if proc.poll() is not None:
                break
            try:
                rss.append(p.memory_info().rss)
                cpu.append(p.cpu_percent(interval=None))
                alive_at = time.perf_counter() - start
            except psutil.Error:
                break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
    stderr = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
    return {
        "agent": name,
        "returncode": proc.returncode,
        "alive_seconds": round(alive_at or 0, 2),
        "rss_mb_median": round(statistics.median(rss) / 1024 / 1024, 2) if rss else None,
        "rss_mb_max": round(max(rss) / 1024 / 1024, 2) if rss else None,
        "cpu_percent_median": round(statistics.median(cpu), 2) if cpu else None,
        "samples": len(rss),
        "stderr_tail": stderr[-800:],
    }


def artifact_size():
    sizes = {}
    if GO_BINARY.exists():
        sizes["go_binary_bytes"] = GO_BINARY.stat().st_size
    if JAVA_JAR.exists():
        sizes["java_jar_bytes"] = JAVA_JAR.stat().st_size
    if PY_BUNDLE.exists():
        sizes["python_bundle_bytes"] = sum(p.stat().st_size for p in PY_BUNDLE.rglob("*") if p.is_file())
    jre = JAVA_HOME / "bin" / "java.exe"
    if jre.exists():
        sizes["java_runtime_bytes"] = sum(p.stat().st_size for p in JAVA_HOME.rglob("*") if p.is_file())
    return sizes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--duration", type=float, default=8)
    parser.add_argument("--only", default="")
    args = parser.parse_args()
    build = subprocess.run(["go", "build", "-o", str(GO_BINARY), "./cmd/aegis-agent"], cwd=GO,
                           capture_output=True, text=True)
    if build.returncode != 0:
        raise SystemExit(build.stderr)
    server, base = start_brain()
    names = [n for n in ("python", "go-sensor", "java", "go-endpoint") if not args.only or n in args.only.split(",")]
    results = []
    try:
        for name in names:
            for run in range(args.runs):
                home = Path(tempfile.mkdtemp(prefix=f"aegis-bench-{name}-"))
                if name == "python":
                    prepare_python(home, base)
                elif name == "java":
                    prepare_java(home, base)
                else:
                    prepare_go(home, base, "endpoint" if name == "go-endpoint" else "sensor")
                result = sample(name, home, base, args.duration)
                result["run"] = run + 1
                results.append(result)
                shutil.rmtree(home, ignore_errors=True)
    finally:
        server.shutdown()
        server.server_close()
    request_counts = dict(sorted(Brain.counts.items()))
    OUT.mkdir(parents=True, exist_ok=True)
    payload = {
        "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": sys.platform,
        "python": sys.version,
        "java": subprocess.run([str(JAVA_HOME / "bin" / "java.exe"), "-version"], capture_output=True, text=True).stderr.splitlines()[:1],
        "runs": args.runs,
        "duration_seconds": args.duration,
        "results": results,
        "fake_brain_requests": request_counts,
        "artifacts": artifact_size(),
    }
    out = OUT / "agents-ab.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
