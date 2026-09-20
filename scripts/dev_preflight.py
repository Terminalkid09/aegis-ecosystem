#!/usr/bin/env python3
"""Dev preflight (audit F-04): verifica i tool essenziali con messaggi chiari.

Controlla Python, Node, Java, Docker, porte e file .env. Exit 0 = ok,
exit 1 = manca qualcosa (con hint di installazione). Non modifica nulla.

Uso: python scripts/dev_preflight.py [--json]
"""
import argparse
import json
import os
import shutil
import socket
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

CHECKS = []


def check(name, ok, hint=""):
    CHECKS.append({"name": name, "ok": bool(ok), "hint": "" if ok else hint})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    check("python>=3.10", sys.version_info >= (3, 10),
          "installare Python 3.10+ (CI usa 3.12)")
    check("node", shutil.which("node") is not None,
          "installare Node.js 22+ (frontend build/lint)")
    check("java", shutil.which("java") is not None,
          "installare JDK 21+ (Temurin) per aegis-guard")
    check("mvn", shutil.which("mvn") is not None,
          "installare Maven 3.9+ (oppure ./mvnw se presente)")
    check("docker", shutil.which("docker") is not None,
          "installare Docker 24+ (stack locale e Trivy)")
    check(".env presente", os.path.isfile(os.path.join(REPO, ".env")),
          "copiare .env.example in .env e valorizzare i segreti")
    for port, svc in ((5444, "postgres"), (6388, "redis"), (8000, "brain")):
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect(("127.0.0.1", port))
            open_ = True
        except OSError:
            open_ = False
        finally:
            s.close()
        check(f"porta {port} ({svc}) raggiungibile", open_,
              f"avviare lo stack (docker compose up -d) per test live; "
              f"i test senza DB vengono skippati")

    failed = [c for c in CHECKS if not c["ok"]]
    if args.json:
        print(json.dumps({"failed": len(failed), "checks": CHECKS}, indent=2))
    else:
        for c in CHECKS:
            print(f"[{'PASS' if c['ok'] else 'FAIL'}] {c['name']}"
                  + ("" if c["ok"] else f" -- {c['hint']}"))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
