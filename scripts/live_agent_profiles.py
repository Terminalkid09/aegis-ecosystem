#!/usr/bin/env python3
"""Live test dei tre profili agente contro lo stack Aegis gia' avviato.

Non inventa un Brain finto: usa l'API reale su --base, iscrive host temporanei
con la enroll key del .env, verifica il record e revoca l'agente alla fine.

Uso:
    python scripts/live_agent_profiles.py
    python scripts/live_agent_profiles.py --skip-build
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = ROOT / "aegis-agent"


def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            env[key] = value
    return env


class Api:
    def __init__(self, base: str, token: str = ""):
        self.base = base.rstrip("/")
        self.token = token

    def call(self, method: str, path: str, body=None, headers=None, raw=False, timeout=20):
        data = None if body is None else json.dumps(body).encode()
        h = {"Accept": "application/json"}
        h.update(headers or {})
        if data is not None:
            h["Content-Type"] = "application/json"
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                content = response.read()
                if raw:
                    return response.status, content.decode("utf-8", "replace")
                return response.status, json.loads(content) if content else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:1000]
            return exc.code, detail

    def login(self, email: str, password: str) -> None:
        status, body = self.call("POST", "/api/v1/auth/login",
                                 {"email": email, "password": password})
        if status != 200 or not isinstance(body, dict) or not body.get("access_token"):
            raise RuntimeError(f"login fallito: HTTP {status}: {body}")
        self.token = body["access_token"]

    def agents(self) -> list[dict]:
        status, body = self.call("GET", "/api/v1/telemetry/agents?limit=1000")
        if status != 200:
            raise RuntimeError(f"agents HTTP {status}: {body}")
        return body if isinstance(body, list) else body.get("items", [])

    def find(self, hostname: str) -> dict | None:
        for agent in self.agents():
            if agent.get("hostname") == hostname:
                return agent
        return None


def build_binary() -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    binary = Path(tempfile.gettempdir()) / f"aegis-agent-live{suffix}"
    command = ["go", "build", "-o", str(binary), "./cmd/aegis-agent"]
    result = subprocess.run(command, cwd=AGENT_DIR, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"build fallita:\n{result.stdout}\n{result.stderr}")
    return binary


def profile_env(profile: str, home: Path, base: str, enroll_key: str, hostname: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "AEGIS_AGENT_HOME": str(home),
        "AEGIS_IDENTITY_DIR": str(home),
        "AEGIS_AGENT_PROFILE": profile,
        "NODETRACE_DEVICE_NAME": hostname,
        "AEGIS_ENROLL_KEY": enroll_key,
        "GOTOOLCHAIN": "auto",
        "AEGIS_ETW_ENABLED": "false",
        "AEGIS_SCAN_INTERVAL_MS": "2000",
        "AEGIS_SPOOL_DIR": str(home / "spool"),
        "AEGIS_SECRET_FILE": str(home / "secret.json"),
        "AEGIS_BRAIN_URL": base.rstrip("/") + "/api/v1",
    })
    if profile == "sensor":
        env.update({
            "NODETRACE_REGISTER_URL": base.rstrip("/") + "/api/v1/register",
            "NODETRACE_HEARTBEAT_URL": base.rstrip("/") + "/api/v1/heartbeat",
            "NODETRACE_UPDATE_URL": base.rstrip("/") + "/api/v1/update",
        })
    return env


def run_profile(api: Api, binary: Path, profile: str, base: str,
                enroll_key: str, seconds: int = 14) -> dict:
    stamp = datetime.now().strftime("%H%M%S")
    hostname = f"aegis-live-{profile}-{stamp}"
    home = Path(tempfile.mkdtemp(prefix=f"aegis-{profile}-"))
    env = profile_env(profile, home, base, enroll_key, hostname)
    command = [str(binary), "--profile", profile, "--home", str(home)]
    stderr_path = home / "agent.stderr.log"
    stdout_path = home / "agent.stdout.log"
    with stderr_path.open("w", encoding="utf-8") as stderr, stdout_path.open("w", encoding="utf-8") as stdout:
        process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr, cwd=ROOT)
        deadline = time.time() + seconds
        agent = None
        while time.time() < deadline:
            try:
                agent = api.find(hostname)
            except Exception:
                agent = None
            if agent:
                break
            time.sleep(0.5)
        # Enrollment creates the record; wait for the first authenticated
        # heartbeat/report before declaring the profile live.
        if agent:
            settle = min(8, max(3, seconds - 2))
            time.sleep(settle)
            try:
                agent = api.find(hostname) or agent
            except Exception:
                pass
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    if not agent:
        raise RuntimeError(
            f"{profile}: agente non visibile nel Brain (host={hostname})\n"
            f"stdout:\n{stdout_path.read_text(encoding='utf-8', errors='replace')[-2000:]}\n"
            f"stderr:\n{stderr_text[-3000:]}"
        )
    expected = {"sensor": "nodetrace", "endpoint": "aegis-guard", "unified": "unified"}[profile]
    if agent.get("agent_type") != expected:
        raise RuntimeError(f"{profile}: agent_type={agent.get('agent_type')!r}, atteso {expected!r}")
    if not agent.get("last_seen"):
        raise RuntimeError(f"{profile}: last_seen assente dopo heartbeat: {agent}")
    recent = None
    if profile in ("sensor", "unified"):
        status, recent = api.call("GET", f"/api/v1/telemetry/recent?agent_id={agent.get('agent_id')}&limit=5")
        if status != 200 or not recent:
            raise RuntimeError(f"{profile}: nessuna telemetria recente: HTTP {status}: {recent}")
    return {
        "profile": profile,
        "hostname": hostname,
        "agent_id": agent.get("agent_id"),
        "agent_type": agent.get("agent_type"),
        "capabilities": agent.get("capabilities"),
        "last_seen": agent.get("last_seen"),
        "recent_telemetry": len(recent or []),
        "home": str(home),
        "stderr_tail": stderr_text[-500:],
    }


def deploy_checks(api: Api) -> dict:
    out: dict[str, object] = {}
    status, token = api.call("POST", "/api/v1/deploy/token", {
        "label": "live-unified-audit", "agent_type": "unified",
        "ttl_minutes": 5, "dashboard_remote": True,
    })
    out["token_status"] = status
    if status != 200 or not isinstance(token, dict):
        out["token_error"] = token
        return out
    raw = token["token"]
    out["token_has_unified"] = token.get("agent_type") == "unified"
    for agent in ("unified", "aegis-guard", "nodetrace"):
        status, script = api.call(
            "GET", f"/api/v1/deploy/install.ps1?agent={urllib.parse.quote(agent)}",
            headers={"X-Enroll-Token": raw}, raw=True,
        )
        out[f"ps1_{agent}"] = status
        if agent == "unified" and status == 200:
            out["ps1_unified_branch"] = '"unified"' in script and "AegisAgent" in script
        status, script = api.call(
            "GET", f"/api/v1/deploy/install.sh?agent={urllib.parse.quote(agent)}",
            headers={"X-Enroll-Token": raw}, raw=True,
        )
        out[f"sh_{agent}"] = status
        if agent == "unified" and status == 200:
            out["sh_unified_branch"] = '"unified"' in script and "aegis-agent" in script
    api.call("POST", f"/api/v1/deploy/token/{token.get('id')}/revoke", {})
    status, job = api.call("POST", "/api/v1/deploy/jobs", {
        "agent_type": "unified", "agent_version": "latest",
        "method_default": "oneline",
        "targets": [{"ip_address": "127.0.0.1", "method": "oneline"}],
    })
    out["job_status"] = status
    out["job_manual"] = isinstance(job, dict) and job.get("status") == "manual_required"
    status, rejected = api.call("POST", "/api/v1/deploy/jobs", {
        "agent_type": "aegis-guard", "method_default": "ssh",
        "targets": [{"ip_address": "127.0.0.1", "method": "ssh"}],
    })
    out["ssh_rejected"] = status == 501
    out["ssh_detail"] = rejected
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:8000")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--seconds", type=int, default=14)
    args = parser.parse_args()

    env = load_env(ROOT / ".env")
    enroll_key = env.get("AGENT_ENROLL_KEY", "")
    if not enroll_key:
        raise SystemExit("AGENT_ENROLL_KEY assente in .env")
    api = Api(args.base)
    api.login(env["AEGIS_ADMIN_EMAIL"], env["AEGIS_ADMIN_PASSWORD"])
    binary = Path(tempfile.gettempdir()) / ("aegis-agent-live.exe" if os.name == "nt" else "aegis-agent-live")
    if not args.skip_build:
        binary = build_binary()

    results = []
    for profile in ("sensor", "endpoint", "unified"):
        result = run_profile(api, binary, profile, args.base, enroll_key, args.seconds)
        results.append(result)
        print(f"PASS {profile}: {result['agent_type']} {result['agent_id']} caps={bool(result['capabilities'])} recent={result['recent_telemetry']}")
        try:
            status, body = api.call("POST", f"/api/v1/enroll/agents/{result['agent_id']}/revoke",
                                     {"reason": "live profile test"})
            print(f"  revoke HTTP {status}")
        except Exception as exc:
            print(f"  revoke non eseguito: {exc}")

    checks = deploy_checks(api)
    print("DEPLOY " + json.dumps(checks, ensure_ascii=False, sort_keys=True))
    print("RESULTS " + json.dumps(results, ensure_ascii=False, sort_keys=True))
    ok = all([
        checks.get("token_status") == 200,
        checks.get("token_has_unified") is True,
        checks.get("ps1_unified") == 200,
        checks.get("sh_unified") == 200,
        checks.get("ps1_unified_branch") is True,
        checks.get("sh_unified_branch") is True,
        checks.get("job_status") == 200,
        checks.get("job_manual") is True,
        checks.get("ssh_rejected") is True,
    ])
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
