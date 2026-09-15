#!/usr/bin/env python3
"""Aegis pilot in un solo comando (sostituisce il flusso batch fragile).

Fa: compose up -> attesa readiness con deadline -> avvio agenti host ->
smoke API -> riepilogo con URL. Exit 0 = PILOT UP, 1 = fallimento con
motivo stampato. Idempotente: richiamabile piu' volte.

Uso:
    python scripts/pilot.py [--no-agents] [--wait 120] [--compose-profile ollama]
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BRAIN = "http://127.0.0.1:8000"


def log(msg, kind="*"):
    print(f"[{kind}] {msg}", flush=True)


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True,
                          timeout=kw.pop("timeout", 300), **kw)


def wait_ready(base, deadline_s):
    url = base + "/health/ready"
    end = time.monotonic() + deadline_s
    last = ""
    while time.monotonic() < end:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                data = json.loads(r.read().decode())
            if data.get("status") == "ready":
                return True, ""
            last = f"status={data.get('status')}"
        except Exception as e:  # noqa: BLE001 - atteso durante il boot
            last = str(e)[:100]
        time.sleep(5)
    return False, last


def procs_running():
    """True per (nodetrace, guard-jvm). Solo Windows: altrove solo nodetrace."""
    out = {"nodetrace": False, "guard": False}
    try:
        if os.name != "nt":
            return out
        # Via tasklist (semplice e robusto su Windows).
        ps = subprocess.run(["tasklist", "/FO", "CSV", "/NH"],
                            capture_output=True, text=True, timeout=30)
        low = ps.stdout.lower()
        out["nodetrace"] = "nodetrace-agent.exe" in low
        out["guard"] = False
        for line in low.splitlines():
            if '"java.exe"' in line or line.startswith('"java.exe"'):
                out["guard"] = True
                break
    except Exception:
        pass
    return out


def start_agents():
    """Lancia gli agenti host come fa aegis.bat agents (stessi env/paths)."""
    import shutil
    root = REPO
    node_exe = os.path.join(root, "NodeTrace", "agents", "python",
                            "dist", "nodetrace-agent", "nodetrace-agent.exe")
    guard_jar = os.path.join(root, "aegis-guard", "target", "aegis-guard.jar")
    if not os.path.isfile(node_exe):
        return False, f"manca {node_exe} (build agenti prima)"
    if not os.path.isfile(guard_jar):
        return False, f"manca {guard_jar} (build agenti prima)"
    env = dict(os.environ)
    try:
        with open(os.path.join(root, ".env"), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass
    env["AEGIS_ENROLL_KEY"] = env.get("AGENT_ENROLL_KEY", "")
    for base in ("http://127.0.0.1:8000/api/v1",):
        env["NODETRACE_BASE"] = base
        env["NODETRACE_REGISTER_URL"] = base + "/register"
        env["NODETRACE_UPDATE_URL"] = base + "/update"
        env["NODETRACE_HEARTBEAT_URL"] = base + "/heartbeat"
        env["AEGIS_BRAIN_URL"] = base
        env["AEGIS_GATEWAY_URL"] = base + "/telemetry/report"
    env["AEGIS_SCAN_INTERVAL_MS"] = "10000"
    env["PYTHONUNBUFFERED"] = "1"
    logs = os.path.join(root, "logs")
    os.makedirs(logs, exist_ok=True)
    # Stop precedenti istanze note (best-effort).
    if os.name == "nt":
        for img in ("nodetrace-agent.exe",):
            subprocess.run(["taskkill", "/f", "/im", img],
                           capture_output=True, timeout=30)
    node_log = open(os.path.join(logs, "nodetrace.txt"), "ab")
    subprocess.Popen([node_exe], env=env, stdout=node_log, stderr=subprocess.STDOUT,
                     cwd=os.path.dirname(node_exe))
    # Audit: JRE bundled prima del java di sistema (su PATH c'e' spesso un
    # Java 8 che non apre i jar compilati per Java 21).
    java = None
    for cand in (os.path.join(root, "aegis-guard", "jre-new", "bin", "java.exe"),
                 os.path.join(root, "aegis-guard", "jre", "bin", "java.exe")):
        if os.path.isfile(cand):
            java = cand
            break
    if java is None:
        java = shutil.which("java")
    if java:
        guard_log = open(os.path.join(logs, "guard.txt"), "ab")
        subprocess.Popen([java, "-jar", guard_jar], env=env,
                         stdout=guard_log, stderr=subprocess.STDOUT,
                         cwd=os.path.join(root, "aegis-guard"))
        return True, "nodetrace+guard lanciati (log in logs/)"
    return True, "nodetrace lanciato; java non trovato per guard"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-agents", action="store_true")
    ap.add_argument("--wait", type=int, default=120)
    ap.add_argument("--compose-profile", default="ollama")
    ap.add_argument("--base", default=BRAIN)
    args = ap.parse_args()

    log("AEGIS PILOT: platform + agents + verify")
    log("compose up...")
    r = run(["docker", "compose", "--profile", args.compose_profile, "up", "-d"])
    if r.returncode != 0:
        log(f"compose up fallito:\n{r.stderr[-2000:]}", "!")
        return 1
    log("attesa readiness...")
    ok, detail = wait_ready(args.base, args.wait)
    if not ok:
        log(f"backend non ready: {detail}", "!")
        return 1
    log("backend ready.")
    if not args.no_agents:
        ok, detail = start_agents()
        log(detail, "+" if ok else "!")
        if not ok:
            return 1
        time.sleep(8)
        procs = procs_running()
        log(f"processi agenti: nodetrace={procs['nodetrace']} guard-jvm={procs['guard']}")
    log("smoke API...")
    r = run([sys.executable, os.path.join(REPO, "scripts", "api_smoke.py"),
             "--base", args.base])
    print(r.stdout[-1500:])
    if r.returncode != 0:
        log("API smoke FAILED", "!")
        return 1
    print("=== PILOT UP ===")
    print("  Dashboard (container): http://localhost:3000")
    print("  Dashboard (dev):       http://localhost:5173  (npm run dev in frontend/)")
    print("  API:                   http://127.0.0.1:8000/api/v1")
    print("  Health:                http://127.0.0.1:8000/health/ready")
    print("  Logs:                  logs/nodetrace.txt, logs/guard.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
