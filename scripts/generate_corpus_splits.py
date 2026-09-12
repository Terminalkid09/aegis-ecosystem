#!/usr/bin/env python3
"""Generatore dataset detection INDIPENDENTI (M4 audit F2).

Crea gli split `validation` e `regression` sotto aegis-brain/tests/corpus/:
    - validation: eventi mai visti in training (host/timestamp/varianti diverse),
      usati per misurare GENERALIZZAZIONE, non overfitting.
    - regression: incidenti noti del passato che NON devono mai ri-regredire.
Ogni split include manifest.json (seed, sha256, conteggi, data, scopo).

Training = corpus esistente (benign/suspicious/malformed alla radice).

Uso:
    python scripts/generate_corpus_splits.py            # genera entrambi gli split
    python scripts/generate_corpus_splits.py --dry-run  # solo validazione logica

Il generatore AUTO-VERIFICA ogni linea sospetta contro le regole attive:
    - ogni linea suspicious deve attivare almeno la regola attesa (TP);
    - ogni linea benigna non deve attivare alcuna regola (FP = 0).
Se la verifica fallisce, il generatore esce con errore (fail-closed).
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "aegis-brain"))

from app.services.replay import run_static_replay, score_corpus, DATASET_VERSION  # noqa: E402

CORPUS_DIR = os.path.join(REPO, "aegis-brain", "tests", "corpus")
VALIDATION_SEED = 20261001
REGRESSION_SEED = 20260815
HOST_DAYS = 1.0

TS = "2026-10-01T08:00:00+00:00"


# ── VALIDATION: varianti NON presenti in training ──────────────────────────
def validation_suspicious():
    return [
        # S001 known attack tool (varianti diverse da mimikatz/nmap del training)
        {"expect": ["AEGIS-S001"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5001, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "wmiexec.exe", "process_path": "C:\\Temp\\wmiexec.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        {"expect": ["AEGIS-S001"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5002, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "msfvenom", "process_path": "/tmp/msfvenom", "user": "root", "os": "Linux", "hostname": "val-srv-01"}},
        # S002 suspicious parent-child: winword -> cscript.exe (training usava powershell)
        {"expect": ["AEGIS-S002"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5003, "parent_pid": 2501, "parent_process_name": "winword.exe", "process_name": "cscript.exe", "process_path": "C:\\Windows\\System32\\cscript.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        # S003 malware family: lockbit
        {"expect": ["AEGIS-S003"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5004, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "lockbit.exe", "process_path": "C:\\Users\\jdoe\\Downloads\\lockbit.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        # S004 suspicious execution path: eseguibile in %TEMP%
        {"expect": ["AEGIS-S004"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5005, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "setup_crack.bat", "process_path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\setup_crack.bat", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        # S005 privilege escalation: firefox as SYSTEM (training: chrome)
        {"expect": ["AEGIS-S005"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5006, "parent_pid": 600, "parent_process_name": "services.exe", "process_name": "firefox.exe", "process_path": "C:\\Program Files\\Mozilla Firefox\\firefox.exe", "user": "SYSTEM", "os": "Windows", "hostname": "val-ws-01"}},
        # S006 double extension: scan.pdf.exe
        {"expect": ["AEGIS-S006"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5007, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "scan.pdf.exe", "process_path": "C:\\Users\\jdoe\\Desktop\\scan.pdf.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        # S007 encoded command: -EncodedCommand variant
        {"expect": ["AEGIS-S007"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5008, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "powershell.exe", "process_path": "C:\\PowerShell\\powershell.exe -ea Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==", "command_line": "powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        # S008 persistence path: systemd unit
        {"expect": ["AEGIS-S008"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5009, "parent_pid": 1, "parent_process_name": "systemd", "process_name": "update-bot", "process_path": "/etc/systemd/system/update-bot", "user": "root", "os": "Linux", "hostname": "val-srv-01"}},
        # S009 script interpreter: python3.exe in roaming (non coperto da altre regole)
        {"expect": ["AEGIS-S009"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5010, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "python3.exe", "process_path": "C:\\Users\\jdoe\\AppData\\Roaming\\python3.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        # S010 network tool in suspicious path: wget.exe in temp (in NETWORK_TOOLS; path temp => anche S004)
        {"expect": ["AEGIS-S004", "AEGIS-S010"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5011, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "wget.exe", "process_path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\wget.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        # S011 DLL hijacking: dll in temp
        {"expect": ["AEGIS-S011"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5012, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "shellex.dll", "process_path": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\shellex.dll", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        # S012 LOLBin abuse: msiexec.exe from desktop
        {"expect": ["AEGIS-S012"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5013, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "msiexec.exe", "process_path": "C:\\Users\\jdoe\\Desktop\\msiexec.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        # S013 high thread count variant
        {"expect": ["AEGIS-S013"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5014, "parent_pid": 1, "parent_process_name": "systemd", "process_name": "java", "process_path": "/opt/app/java", "user": "app", "os": "Linux", "thread_count": 750, "hostname": "val-srv-01"}},
        # S014 network beacon: certutil -> public IP
        {"expect": ["AEGIS-S014"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5015, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "certutil.exe", "process_path": "C:\\Windows\\System32\\certutil.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01", "network_connections": [{"remote": "203.0.113.7:443", "state": "ESTABLISHED"}]}},
        # S015 persistence autorun: sysupdate.exe
        {"expect": ["AEGIS-S015"], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 5016, "parent_pid": 600, "parent_process_name": "services.exe", "process_name": "sysupdate.exe", "process_path": "C:\\Windows\\System32\\sysupdate.exe", "user": "SYSTEM", "os": "Windows", "hostname": "val-ws-01"}},
    ]


def validation_benign():
    return [
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 6000, "parent_pid": 500, "parent_process_name": "winlogon.exe", "process_name": "explorer.exe", "process_path": "C:\\Windows\\explorer.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 6001, "parent_pid": 600, "parent_process_name": "services.exe", "process_name": "svchost.exe", "process_path": "C:\\Windows\\System32\\svchost.exe", "user": "SYSTEM", "os": "Windows", "hostname": "val-ws-01"}},
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 6002, "parent_pid": 500, "parent_process_name": "winlogon.exe", "process_name": "dwm.exe", "process_path": "C:\\Windows\\System32\\dwm.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 1, "parent_pid": 0, "process_name": "systemd", "process_path": "/usr/lib/systemd/systemd", "user": "root", "os": "Linux", "hostname": "val-srv-01"}},
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 6003, "parent_pid": 1, "parent_process_name": "systemd", "process_name": "nginx", "process_path": "/usr/sbin/nginx", "user": "root", "os": "Linux", "hostname": "val-srv-01"}},
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 6004, "parent_pid": 1, "parent_process_name": "systemd", "process_name": "sshd", "process_path": "/usr/sbin/sshd", "user": "root", "os": "Linux", "hostname": "val-srv-01"}},
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 6005, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "chrome.exe", "process_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 6006, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "notepad.exe", "process_path": "C:\\Windows\\System32\\notepad.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 6007, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "msedge.exe", "process_path": "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe", "user": "jdoe", "os": "Windows", "hostname": "val-ws-01"}},
    ]


def validation_malformed():
    return [
        "not json {{{{ broken",
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": "not-a-date", "event_type": "PROCESS_CREATED", "process_name": "x.exe"}},
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "seq": -1}},
        {"expect": [], "event": {"agent_id": "val-host-01", "timestamp": TS, "event_type": "NOT_A_TYPE", "process_name": "x.exe"}},
    ]


# ── REGRESSION: casi noti del passato che non devono ri-regredire ─────────
def regression_suspicious():
    return [
        # Incidente storico 1: attack tool noto — S001
        {"expect": ["AEGIS-S001"], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7001, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "mimikatz.exe", "process_path": "C:\\Temp\\mimikatz.exe", "user": "jdoe", "os": "Windows", "hostname": "reg-ws-01"}},
        # Incidente storico 2: macro office -> powershell — S002+S007
        {"expect": ["AEGIS-S002", "AEGIS-S007"], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7002, "parent_pid": 2501, "parent_process_name": "winword.exe", "process_name": "powershell.exe", "process_path": "C:\\Users\\vic\\AppData\\Local\\Temp\\p.ps1 -e SQBuAHYAbwBrAGEAAAA=", "command_line": "powershell.exe -e SQBuAHYAbwBrAGEAAAA=", "user": "vic", "os": "Windows", "hostname": "reg-ws-01"}},
        # Incidente storico 3: ransomware lockbit family — S003
        {"expect": ["AEGIS-S003"], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7003, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "lockbit.exe", "process_path": "C:\\Users\\vic\\Downloads\\lockbit.exe", "user": "vic", "os": "Windows", "hostname": "reg-ws-01"}},
        # Incidente storico 4: doppia estensione invoice
        {"expect": ["AEGIS-S006"], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7004, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "invoice.pdf.exe", "process_path": "C:\\Users\\vic\\Downloads\\invoice.pdf.exe", "user": "vic", "os": "Windows", "hostname": "reg-ws-01"}},
        # Incidente storico 5: privilege escalation chrome-as-SYSTEM
        {"expect": ["AEGIS-S005"], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7005, "parent_pid": 600, "parent_process_name": "services.exe", "process_name": "chrome.exe", "process_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "user": "SYSTEM", "os": "Windows", "hostname": "reg-ws-01"}},
        # Incidente storico 6: persistence autorun svch0st
        {"expect": ["AEGIS-S015"], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7006, "parent_pid": 600, "parent_process_name": "services.exe", "process_name": "svch0st.exe", "process_path": "C:\\Windows\\System32\\svch0st.exe", "user": "SYSTEM", "os": "Windows", "hostname": "reg-ws-01"}},
        # Incidente storico 7: rete verso pubblico da certutil
        {"expect": ["AEGIS-S014"], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7007, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "certutil.exe", "process_path": "C:\\Windows\\System32\\certutil.exe", "user": "vic", "os": "Windows", "hostname": "reg-ws-01", "network_connections": [{"remote": "8.8.8.8:443", "state": "ESTABLISHED"}]}},
    ]


def regression_benign():
    return [
        {"expect": [], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7100, "parent_pid": 500, "parent_process_name": "winlogon.exe", "process_name": "explorer.exe", "process_path": "C:\\Windows\\explorer.exe", "user": "jdoe", "os": "Windows", "hostname": "reg-ws-01"}},
        {"expect": [], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7101, "parent_pid": 600, "parent_process_name": "services.exe", "process_name": "svchost.exe", "process_path": "C:\\Windows\\System32\\svchost.exe", "user": "SYSTEM", "os": "Windows", "hostname": "reg-ws-01"}},
        {"expect": [], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7102, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "chrome.exe", "process_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "user": "jdoe", "os": "Windows", "hostname": "reg-ws-01"}},
        # Regressione critica: winword -> notepad NON deve triggerare (era un vecchio FP)
        {"expect": [], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7103, "parent_pid": 2501, "parent_process_name": "winword.exe", "process_name": "notepad.exe", "process_path": "C:\\Windows\\System32\\notepad.exe", "user": "jdoe", "os": "Windows", "hostname": "reg-ws-01"}},
        # Regressione critica: curl.exe da System32 NON deve triggerare
        {"expect": [], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7104, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "curl.exe", "process_path": "C:\\Windows\\System32\\curl.exe", "user": "jdoe", "os": "Windows", "hostname": "reg-ws-01"}},
        # Regressione critica: chrome con connessioni outbound non è beacon (bassa rischiosità)
        {"expect": [], "event": {"agent_id": "reg-host-01", "timestamp": TS, "event_type": "PROCESS_CREATED", "pid": 7105, "parent_pid": 1000, "parent_process_name": "explorer.exe", "process_name": "chrome.exe", "process_path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "user": "jdoe", "os": "Windows", "hostname": "reg-ws-01", "network_connections": [{"remote": "1.2.3.4:443", "state": "ESTABLISHED"}]}},
    ]


def regression_malformed():
    return [
        "garbage line {{{ not json",
        {"expect": [], "event": {"agent_id": "reg-host-01", "timestamp": "2026-08-15T00:00:00+00:00", "event_type": "PROCESS_CREATED", "process_name": "legit.exe"}},
    ]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_split(name: str, split_data: dict, seed: int) -> dict:
    split_dir = os.path.join(CORPUS_DIR, name)
    os.makedirs(split_dir, exist_ok=True)
    manifest = {
        "split": name,
        "dataset_version": DATASET_VERSION,
        "seed": seed,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "purpose": split_data["purpose"],
        "host_days": HOST_DAYS,
        "files": {},
    }
    for fname, rows in {
        "benign.jsonl": split_data["benign"],
        "suspicious.jsonl": split_data["suspicious"],
        "malformed.jsonl": split_data["malformed"],
    }.items():
        payload = "".join(
            line if isinstance(line, str) else json.dumps(line) + "\n"
            for line in rows
        )
        with open(os.path.join(split_dir, fname), "w", encoding="utf-8") as f:
            f.write(payload)
        manifest["files"][fname] = {
            "sha256": _sha256(payload.encode("utf-8")),
            "bytes": len(payload.encode("utf-8")),
            "lines": len(rows),
        }
    manifest_path = os.path.join(split_dir, "manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    return manifest


def verify_split(name: str, split_data: dict) -> dict:
    """Run delle regole reali sul NUOVO split: ogni sospetta deve fare TP,
    ogni benigna deve fare 0 hit."""
    findings = {"name": name, "fp": 0, "fn": 0, "broke": []}
    for i, row in enumerate(split_data["suspicious"]):
        expect = {str(x).upper() for x in row.get("expect", [])}
        rep = run_static_replay([row])
        got = {h["rule_id"] for h in rep["hits"]}
        if not (expect & got):
            findings["fn"] += 1
            findings["broke"].append(f"suspicious[{i}] expect={expect} got={got}")
    for i, row in enumerate(split_data["benign"]):
        rep = run_static_replay([row])
        if rep["hits"]:
            findings["fp"] += 1
            findings["broke"].append(f"benign[{i}] unexpected hits={[h['rule_id'] for h in rep['hits']]}")
    return findings


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="verifica logica senza scrivere file")
    args = ap.parse_args()

    splits = {
        "validation": {
            "purpose": "Eventi mai visti in training: misura la generalizzazione "
                       "delle regole (anti-overfitting). Host/timestamp/procedure diversi.",
            "suspicious": validation_suspicious(),
            "benign": validation_benign(),
            "malformed": validation_malformed(),
        },
        "regression": {
            "purpose": "Incidenti noti del passato che devono continuare a triggerare, "
                       "più casi benigni che in passato erano falsi positivi.",
            "suspicious": regression_suspicious(),
            "benign": regression_benign(),
            "malformed": regression_malformed(),
        },
    }

    ok = True
    if args.dry_run:
        print("DRY-RUN: verifica logica dei nuovi split contro le regole attive...")
        for name, data in splits.items():
            f = verify_split(name, data)
            status = "OK " if not f["broke"] else "FAIL"
            print(f"  [{status}] {name}: fn={f['fn']} fp={f['fp']}")
            for line in f["broke"]:
                print(f"       - {line}")
            ok = ok and not f["broke"]
        print("TIP: usa `--dry-run` senza flag per generare i file.")
        return 0 if ok else 1

    for name, data in splits.items():
        f = verify_split(name, data)
        if f["broke"]:
            print(f"[FAIL] {name}: the new dataset does not match current rules")
            for line in f["broke"]:
                print(f"    - {line}")
            ok = False
            continue
        seed = VALIDATION_SEED if name == "validation" else REGRESSION_SEED
        _write_split(name, data, seed)
        total_lines = len(data["benign"]) + len(data["suspicious"]) + len(data["malformed"])
        print(f"[OK] {name}/ generated ({total_lines} lines)")
        print(f"     manifest: {os.path.join(CORPUS_DIR, name, 'manifest.json')}")

    # Validazione finale end-to-end via score_corpus(split=...)
    print("Final end-to-end check per split...")
    for name in ("validation", "regression"):
        rep = score_corpus(split=name)
        print(f"  {name}: tp={rep['tp']} fp={rep['fp']} fn={rep['fn']} f1={rep['f1']} "
              f"fp/host-day={rep['false_positives_per_host_day']}")
        ok = ok and rep["fp"] == 0 and rep["fn"] == 0 and rep["f1"] == 1.0

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())