#!/usr/bin/env python3
"""API smoke contro stack live (audit F7, ramo eseguito).

Controlli senza autenticazione: /health/live, /health/ready, /metrics.
Exit 0 = ALL PASS, 1 = almeno un FAIL. Output umano + riepilogo JSON con --json.

Uso: python scripts/api_smoke.py [--base http://127.0.0.1:8000] [--json]
"""
import argparse
import json
import sys
import urllib.request

CHECKS = []


def check(name, fn):
    try:
        detail = fn()
        CHECKS.append({"name": name, "status": "pass", "detail": detail})
    except Exception as e:  # noqa: BLE001 - smoke: ogni errore e' un FAIL
        CHECKS.append({"name": name, "status": "fail", "detail": str(e)[:200]})


def get(base, path, timeout=10):
    req = urllib.request.Request(base + path, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    base = args.base.rstrip("/")

    def live():
        status, body = get(base, "/health/live")
        assert status == 200, f"HTTP {status}"
        data = json.loads(body)
        assert data.get("status") == "alive", data
        assert "checks" not in data, "liveness deve essere alive-only (audit F4)"
        return f"alive, uptime_s={data.get('uptime_s')}"

    def ready():
        status, body = get(base, "/health/ready")
        assert status == 200, f"HTTP {status}"
        data = json.loads(body)
        assert data.get("status") in {"ready", "not_ready"}, data
        checks = data.get("checks", {})
        for name in ("database", "redis", "pipeline", "pki", "mtls"):
            assert name in checks, f"check mancante: {name}"
        return f"{data['status']}: " + ", ".join(
            f"{k}={v.get('status')}" for k, v in checks.items())

    def metrics():
        status, body = get(base, "/metrics")
        assert status == 200, f"HTTP {status}"
        text = body.decode("utf-8", errors="replace")
        assert "aegis_http_requests_total" in text, "metrica http assente"
        assert "# TYPE " in text and "# HELP " in text, "directive Prometheus assenti"
        return f"{len(text.splitlines())} righe exposition"

    check("liveness alive-only", live)
    check("readiness full checks", ready)
    check("metrics exposition", metrics)

    failed = sum(1 for c in CHECKS if c["status"] == "fail")
    if args.json:
        print(json.dumps({"base": base, "failed": failed, "checks": CHECKS}, indent=2))
    else:
        for c in CHECKS:
            print(f"[{c['status'].upper()}] {c['name']}: {c['detail']}")
        print("ALL PASS" if failed == 0 else f"{failed} FAILURES")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
