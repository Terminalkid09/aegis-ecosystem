#!/usr/bin/env python3
"""Soak pilot (audit P2): N agenti sintetici contro stack live per T secondi.

Flusso reale completo: enroll -> heartbeat/report autenticati -> verifica
contatori (accepted/duplicates/errors + events_lost lato server).
Exit 0 = PASS (zero persi, zero errori 5xx), 1 = FAIL.

Uso:
    python scripts/pilot_soak.py [--agents 10] [--duration 300] [--base http://127.0.0.1:8000]
Legge AGENT_ENROLL_KEY e porte da .env (mai segreti in argv).

Nota: crea agenti hostname "soak-*" nel DB di sviluppo (etichettati,
innocui). Non usare contro produzione.
"""
import argparse
import json
import os
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load_dotenv(path):
    env = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return env


def http_json(method, url, payload=None, headers=None, timeout=15):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json",
                                          **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode()[:200]
        except Exception:
            body = ""
        return e.code, {"_http_error": e.code, "_body": body}


def server_lost(base):
    # Somma TUTTE le serie lost (con o senza label reason=...).
    try:
        req = urllib.request.Request(base + "/metrics")
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read().decode()
        total = 0
        found = False
        for line in text.splitlines():
            if line.startswith("aegis_events_lost_total"):
                try:
                    total += int(float(line.split()[-1]))
                    found = True
                except (ValueError, IndexError):
                    pass
        return total if found else 0
    except Exception:
        pass
    return None


def agent_worker(base, enroll_key, tag, stop_at, stats, lock):
    hostname = f"soak-{tag}"
    code, reg = http_json("POST", base + "/api/v1/enroll/enroll",
                          {"hostname": hostname, "os": "Linux", "enroll_key": enroll_key})
    if code != 200 or "agent_secret" not in reg:
        with lock:
            stats["enroll_fail"] += 1
        return
    agent_id, secret = reg["agent_id"], reg["agent_secret"]
    headers = {"X-Agent-Id": agent_id, "Authorization": f"Bearer {secret}"}
    i = 0
    while time.monotonic() < stop_at:
        i += 1
        code, _ = http_json("POST", base + "/api/v1/telemetry/heartbeat",
                            {"device_id": agent_id, "agent_version": "soak-1.0"},
                            headers)
        with lock:
            stats["heartbeat"] += 1
            if code != 200:
                stats["errors"] += 1
        payload = {
            "agent_id": agent_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "PROCESS_CREATED", "pid": 1000 + (i % 500),
            "process_name": "notepad.exe",
            "process_path": "C:\\Windows\\System32\\notepad.exe",
            "hostname": hostname, "os": "Windows",
            "event_id": f"soak-{tag}-{i}",
        }
        code, body = http_json("POST", base + "/api/v1/telemetry/report",
                               payload, headers)
        with lock:
            stats["reports"] += 1
            if code != 200:
                stats["errors"] += 1
            elif body.get("status") == "duplicate":
                stats["duplicates"] += 1
            else:
                stats["accepted"] += 1
        time.sleep(2)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--agents", type=int, default=10)
    ap.add_argument("--duration", type=int, default=300)
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    args = ap.parse_args()

    env = load_dotenv(os.path.join(REPO, ".env"))
    enroll_key = os.getenv("AGENT_ENROLL_KEY") or env.get("AGENT_ENROLL_KEY", "")
    if not enroll_key:
        print("AGENT_ENROLL_KEY mancante (.env): impossibile enrollare")
        return 2
    tag = datetime.now(timezone.utc).strftime("%H%M%S")
    lost_before = server_lost(args.base)
    stats = {"enroll_fail": 0, "heartbeat": 0, "reports": 0,
             "accepted": 0, "duplicates": 0, "errors": 0}
    lock = threading.Lock()
    stop_at = time.monotonic() + args.duration
    threads = [threading.Thread(target=agent_worker,
                                args=(args.base, enroll_key, f"{tag}-{n}",
                                      stop_at, stats, lock), daemon=True)
               for n in range(args.agents)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    dt = time.monotonic() - t0
    lost_after = server_lost(args.base)
    lost_delta = (lost_after - lost_before) if lost_before is not None and lost_after is not None else None

    print(f"=== Pilot soak: {args.agents} agenti x {args.duration}s ({dt:.0f}s reali) ===")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print(f"  server lost delta: {lost_delta}")
    ok = stats["enroll_fail"] == 0 and stats["errors"] == 0 and lost_delta == 0
    print("SOAK PASS" if ok else "SOAK FAIL")
    print("Nota: agenti soak-* restano nel DB di sviluppo (etichettati).")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
