#!/usr/bin/env python3
"""
Audit Report — report macchina+umano unico, riproducibile con un singolo comando.

Uso:
    python scripts/audit_report.py
    python scripts/audit_report.py --json-only
    python scripts/audit_report.py --skip-slow

Output:
    - stdout: report umano leggibile
    - audit_report.json: report macchina (oggetto JSON con tutti i dati)

Distinzione reale/simulato/non-eseguito per ogni sezione.
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AUDIT_BASETEMP = REPO / ".pytest-audit-temp"

def run(cmd, cwd=None, timeout=300, shell=True, env_extra=None):
    """Esegue un comando e restituisce (stdout, stderr, returncode, duration_s)."""
    t0 = time.monotonic()
    try:
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        if env_extra:
            env.update(env_extra)
        p = subprocess.run(
            cmd, cwd=cwd or str(REPO), shell=shell,
            capture_output=True, text=True, timeout=timeout,
            env=env,
        )
        dt = time.monotonic() - t0
        return p.stdout, p.stderr, p.returncode, dt
    except subprocess.TimeoutExpired:
        return "", f"TIMEOUT after {timeout}s", -1, timeout
    except Exception as e:
        return "", str(e), -1, time.monotonic() - t0

def run_pytest(suite_name, args, cwd=None):
    """Esegue pytest e parse dell'output per estrarre passed/failed/skipped/duration."""
    stdout, stderr, rc, dt = run(
        f'{sys.executable} -m pytest {args} --basetemp "{AUDIT_BASETEMP}"',
        cwd=cwd or str(REPO / "aegis-brain"),
        timeout=600,
    )
    return _parse_pytest(suite_name, stdout, stderr, rc, dt)


def run_maven(cwd):
    """Esegue `mvn -B test` con JAVA_HOME impostato (portabile Windows+Linux)."""
    java_home = os.environ.get(
        "AEGIS_JAVA_HOME",
        r"C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot"
        if platform.system() == "Windows"
        else "/usr/lib/jvm/default-java",
    )
    stdout, stderr, rc, dt = run(
        "mvn -B test",
        cwd=str(cwd),
        timeout=420,
        env_extra={"JAVA_HOME": java_home},
    )
    out = stdout + stderr
    import re
    m = re.search(
        r"Tests run:\s*(\d+),\s*Failures:\s*(\d+),\s*Errors:\s*(\d+),\s*Skipped:\s*(\d+)",
        out,
    )
    if m:
        run_tests = int(m.group(1))
        failures = int(m.group(2))
        errors = int(m.group(3))
        skipped = int(m.group(4))
        return {
            "name": str(cwd.name),
            "passed": run_tests - failures - errors - skipped,
            "failed": failures + errors,
            "skipped": skipped,
            "return_code": rc,
            "duration_s": round(dt, 2),
            "status": "pass" if rc == 0 and failures == 0 and errors == 0 else "fail",
            "real": True,
        }
    return {
        "name": str(cwd.name),
        "passed": 0,
        "failed": -1,
        "skipped": 0,
        "return_code": rc,
        "duration_s": round(dt, 2),
        "status": "fail",
        "real": True,
        "error": "no surefire summary in output",
        "output_tail": out[-1500:],
    }

def _parse_pytest(name, stdout, stderr, rc, dt):
    import re
    out = stdout + stderr
    # "274 passed, 1 warning in 156.08s" or "101 passed in ..."
    m = re.search(r"(\d+) passed", out)
    passed = int(m.group(1)) if m else 0
    m = re.search(r"(\d+) failed", out)
    failed = int(m.group(1)) if m else 0
    m = re.search(r"(\d+) skipped", out)
    skipped = int(m.group(1)) if m else 0
    m = re.search(r"in (\d+\.\d+)s", out)
    duration = float(m.group(1)) if m else dt
    return {
        "name": name,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "return_code": rc,
        "duration_s": round(duration, 2),
        "status": "pass" if rc == 0 and failed == 0 else "fail",
        "real": True,
    }

def git_info():
    branch, _, rc, _ = run("git rev-parse --abbrev-ref HEAD")
    branch = branch.strip() if rc == 0 else "unknown"
    commit, _, rc, _ = run("git rev-parse --short HEAD")
    commit = commit.strip() if rc == 0 else "unknown"
    return {"branch": branch, "commit": commit}

def env_versions():
    versions = {}
    versions["python"] = sys.version.split()[0]
    out, err, rc, _ = run("node --version")
    versions["node"] = out.strip() if rc == 0 and out else "not found"
    # Java via JAVA_HOME-aware java
    java_home = os.environ.get(
        "AEGIS_JAVA_HOME",
        r"C:\Program Files\Eclipse Adoptium\jdk-25.0.2.10-hotspot"
        if platform.system() == "Windows"
        else "/usr/lib/jvm/default-java",
    )
    out, err, rc, _ = run(f'"{java_home}\\bin\\java.exe" -version 2>&1' if platform.system() == "Windows"
                          else f'"{java_home}/bin/java" -version 2>&1')
    out = out or err
    if rc != 0:
        out, err, rc, _ = run("java -version 2>&1")
        out = out or err
    for line in out.splitlines():
        if "version" in line.lower():
            versions["java"] = line.strip()
            break
    else:
        versions["java"] = "not found"
    out, err, rc, _ = run("docker --version")
    versions["docker"] = out.strip() if rc == 0 and out else "not found"
    versions["os"] = f"{platform.system()} {platform.release()} ({platform.machine()})"
    return versions

def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def run_benchmark(skip_slow=False):
    """Esegue il benchmark riproducibile con metadati completi."""
    cmd = f"{sys.executable} {REPO / 'scripts' / 'benchmark.py'} --quick"
    stdout, stderr, rc, dt = run(cmd, timeout=300)
    return {
        "status": "pass" if rc == 0 else "fail",
        "real": True,
        "simulated": True,
        "duration_s": round(dt, 2),
        "output": stdout.strip(),
        "error": stderr.strip() if rc != 0 else None,
    }

def run_replay():
    """Esegue replay_report.py."""
    cmd = f"{sys.executable} {REPO / 'scripts' / 'replay_report.py'} --all --json"
    stdout, stderr, rc, dt = run(cmd, timeout=120)
    try:
        data = json.loads(stdout)
    except Exception:
        data = {"raw": stdout.strip()}
    return {
        "status": "pass" if rc == 0 else "fail",
        "real": True,
        "simulated": False,
        "duration_s": round(dt, 2),
        "data": data,
    }

def run_frontend():
    """Build + lint frontend."""
    fe_dir = REPO / "frontend"
    results = {}
    npm = "npm.cmd" if platform.system() == "Windows" else "npm"
    for label, cmd in [("build", [npm, "run", "build"]), ("lint", [npm, "run", "lint"] )]:
        stdout, stderr, rc, dt = run(cmd, cwd=str(fe_dir), timeout=120, shell=False)
        results[label] = {
            "status": "pass" if rc == 0 else "fail",
            "duration_s": round(dt, 2),
            "return_code": rc,
            "real": True,
            "output_tail": (stdout + stderr)[-1000:] if rc != 0 else None,
        }
    return results

def run_compose_config():
    """Valida tutti i file compose."""
    configs = [
        ("base", "docker compose -f docker-compose.yml config -q"),
        # Il profilo prod richiede esplicitamente il segreto; usiamo qui un
        # placeholder temporaneo per verificare l'interpolazione senza esporre
        # credenziali reali.
        ("prod", "set \"BACKUP_PASSPHRASE=audit-placeholder-only\" && docker compose -f docker-compose.yml -f docker-compose.prod.yml config -q"),
        ("mtls", "docker compose -f docker-compose.yml -f docker-compose.mtls.yml config -q"),
    ]
    results = {}
    for name, cmd in configs:
        _, stderr, rc, dt = run(cmd, timeout=30)
        results[name] = {
            "status": "pass" if rc == 0 else "fail",
            "duration_s": round(dt, 2),
            "return_code": rc,
            "error_tail": stderr[-1000:] if rc != 0 else None,
        }
    return results

def run_git_diff_check():
    stdout, stderr, rc, dt = run("git diff --check", timeout=30)
    return {
        "status": "pass" if rc == 0 else "warn",
        "return_code": rc,
    }

def run_scans(skip_slow=False):
    """pip-audit + npm audit (Trivy richiede Docker, skippabile con --skip-slow)."""
    results = {}
    # pip-audit (brain requirements)
    _, _, rc, dt = run(
        f"{sys.executable} -m pip_audit -r {REPO / 'aegis-brain' / 'requirements.txt'}",
        timeout=300,
    )
    results["pip_audit"] = {"return_code": rc, "status": "pass" if rc == 0 else "fail", "real": True}

    # npm audit
    _, _, rc, dt = run("npm audit --audit-level=high", cwd=str(REPO / "frontend"), timeout=120)
    results["npm_audit"] = {"return_code": rc, "status": "pass" if rc == 0 else "fail", "real": True}

    return results

def run_installer_checks():
    stdout, stderr, rc, dt = run(
        f"powershell -ExecutionPolicy Bypass -File {REPO / 'scripts' / 'test-installers.ps1'}",
        timeout=120,
    )
    return {
        "status": "pass" if rc == 0 else "fail",
        "return_code": rc,
        "output": stdout.strip()[:500],
        "real": True,
    }

def corpus_info():
    """Info sui dataset detection (corpus)."""
    corpus_dir = REPO / "aegis-brain" / "tests" / "corpus"
    files = {}
    for f in sorted(corpus_dir.rglob("*.jsonl")):
        relative = f.relative_to(corpus_dir).as_posix()
        lines = sum(1 for _ in open(f, encoding="utf-8"))
        files[relative] = {
            "lines": lines,
            "sha256": _sha256_file(f),
            "bytes": f.stat().st_size,
        }
    return files

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json-only", action="store_true")
    ap.add_argument("--skip-slow", action="store_true")
    args = ap.parse_args()

    report = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "git": git_info(),
        "environment": env_versions(),
        "corpus": corpus_info(),
        "suites": {},
    }

    suites = report["suites"]

    print("=== Aegis Pilot Audit Report ===")
    print(f"Timestamp: {report['timestamp']}")
    print(f"Git: {report['git']['branch']}@{report['git']['commit']}")
    for k, v in report["environment"].items():
        print(f"  {k}: {v}")
    print()

    # Brain integration tests
    print("[1/12] Brain integration tests...")
    suites["brain"] = run_pytest("brain", "tests --tb=no")
    b = suites["brain"]
    print(f"  {b['passed']} passed, {b['failed']} failed, {b['skipped']} skipped ({b['duration_s']}s)")

    # Guard tests
    print("[2/12] Guard tests (Maven)...")
    suites["guard"] = run_maven(REPO / "aegis-guard")
    g = suites["guard"]
    print(f"  {g['passed']} passed, {g['failed']} failed, {g['skipped']} skipped ({g['duration_s']}s)")

    # Link tests
    print("[3/12] Link tests (Maven)...")
    suites["link"] = run_maven(REPO / "aegis-link")
    lk = suites["link"]
    print(f"  {lk['passed']} passed, {lk['failed']} failed, {lk['skipped']} skipped ({lk['duration_s']}s)")

    # NodeTrace tests
    print("[4/12] NodeTrace tests...")
    suites["nodetrace"] = run_pytest(
        "nodetrace",
        "--rootdir=. tests --tb=no",
        cwd=REPO / "NodeTrace" / "agents" / "python",
    )
    nt = suites["nodetrace"]
    print(f"  {nt['passed']} passed, {nt['failed']} failed, {nt['skipped']} skipped ({nt['duration_s']}s)")

    # eBPF contract
    print("[5/12] eBPF contract...")
    stdout, stderr, rc, dt = run(f"{sys.executable} aegis-ebpf/check-contract.py")
    contract_passes = sum(1 for line in (stdout + stderr).splitlines() if line.startswith("PASS"))
    suites["contract"] = {
        "name": "contract",
        "passed": contract_passes,
        "failed": 0 if rc == 0 else 1,
        "return_code": rc,
        "duration_s": round(dt, 2),
        "status": "pass" if rc == 0 else "fail",
        "real": True,
    }
    c = suites["contract"]
    print(f"  {c['status']} ({c['duration_s']}s)")

    # Frontend build + lint
    print("[6/12] Frontend build + lint...")
    suites["frontend"] = run_frontend()
    for label, r in suites["frontend"].items():
        print(f"  {label}: {r['status']} ({r['duration_s']}s)")

    # Compose configs
    print("[7/12] Compose config validation...")
    suites["compose"] = run_compose_config()
    for name, r in suites["compose"].items():
        print(f"  {name}: {r['status']}")

    # Replay
    print("[8/12] Detection replay...")
    suites["replay"] = run_replay()
    r = suites["replay"].get("data", {})
    if isinstance(r, dict) and "training" in r:
        for split, split_report in r.items():
            print(f"  {split}: F1={split_report.get('f1', '?')}, "
                  f"TP={split_report.get('tp', '?')}, FP={split_report.get('fp', '?')}, "
                  f"FN={split_report.get('fn', '?')}")

    # Benchmark
    if not args.skip_slow:
        print("[9/12] Benchmark...")
        suites["benchmark"] = run_benchmark()
    else:
        suites["benchmark"] = {"status": "skipped", "real": False, "note": "skipped with --skip-slow"}
    print(f"  {suites['benchmark']['status']}")

    # Security scans
    print("[10/12] Security scans...")
    suites["scans"] = run_scans(skip_slow=args.skip_slow)
    for label, r in suites["scans"].items():
        print(f"  {label}: {r['status']}")

    # Installer checks
    print("[11/12] Installer checks...")
    suites["installers"] = run_installer_checks()
    print(f"  {suites['installers']['status']}")

    # git diff
    print("[12/12] git diff --check...")
    suites["git_diff"] = run_git_diff_check()
    print(f"  {suites['git_diff']['status']}")

    # Summary
    def flatten_numbers(value, key):
        if not isinstance(value, dict):
            return 0
        own = value.get(key, 0)
        own = own if isinstance(own, (int, float)) else 0
        return own + sum(flatten_numbers(child, key) for child in value.values())

    def status_ok(value):
        if not isinstance(value, dict):
            return True
        status = value.get("status")
        if status in {"pass", "skipped"}:
            return True
        if status == "fail":
            return False
        nested = [child for child in value.values() if isinstance(child, dict)]
        return all(status_ok(child) for child in nested)

    total_passed = sum(flatten_numbers(s, "passed") for s in suites.values())
    total_failed = sum(flatten_numbers(s, "failed") for s in suites.values())
    all_pass = all(status_ok(s) for s in suites.values())

    report["summary"] = {
        "total_passed": total_passed,
        "total_failed": total_failed,
        "all_pass": all_pass,
        "suites_real": sum(1 for s in suites.values() if isinstance(s, dict) and s.get("real")),
        "suites_simulated": sum(1 for s in suites.values() if isinstance(s, dict) and s.get("simulated")),
        "suites_not_run": sum(1 for s in suites.values() if isinstance(s, dict) and not s.get("real") and not s.get("simulated")),
    }

    # Write machine report
    report_path = REPO / "audit_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)

    # Human report
    if not args.json_only:
        print()
        print("=" * 60)
        print("SUMMARY")
        print("=" * 60)
        print(f"Total passed:  {total_passed}")
        print(f"Total failed:  {total_failed}")
        print(f"Real suites:   {report['summary']['suites_real']}")
        print(f"Simulated:     {report['summary']['suites_simulated']}")
        print(f"Not run:       {report['summary']['suites_not_run']}")
        print(f"Overall:       {'ALL PASS' if all_pass else 'FAILURES DETECTED'}")
        print(f"Report JSON:   {report_path}")
        print()

        # Detection details
        rd = suites.get("replay", {}).get("data", {})
        if rd:
            print("--- Detection Replay ---")
            for field in ["dataset_version", "precision", "recall", "f1",
                          "tp", "fp", "fn", "false_positives_per_host_day",
                          "mttd_note"]:
                if field in rd:
                    print(f"  {field}: {rd[field]}")
            print()

    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
