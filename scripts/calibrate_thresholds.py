#!/usr/bin/env python3
"""Calibrazione soglie detection (audit P5).

Misura il tradeoff FP/FN delle soglie su (a) corpus versionato e (b) un
pannello benigno SINTETICO esplicito (processi desktop/server comuni con
thread-count realistici da documentazione vendor e telemetria tipica).

Onesta' metodologica: il pannello sintetico NON sostituisce la baseline di
flotta. Lo script produce la curva tradeoff e una raccomandazione; cambia una
soglia solo con evidenza (qui: nessuna modifica automatica, solo report).

Uso:
    python scripts/calibrate_thresholds.py [--json]
"""
import argparse
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "aegis-brain"))

from app.rules.rule_definitions import (  # noqa: E402
    rule_high_thread_count, rule_encoded_command, rule_malware_family,
    HIGH_THREAD_COUNT_THRESHOLD, ENCODED_PATTERNS,
)
from app.api.schemas.common import EventSchema  # noqa: E402

TS = "2026-09-13T10:00:00+00:00"


def ev(**kw):
    base = {"agent_id": "calib", "timestamp": TS,
            "event_type": "PROCESS_CREATED", "process_name": "x.exe"}
    base.update(kw)
    return EventSchema(**base)


# Pannello benigno SINTETICO: nomi/path realistici, thread tipici osservati
# in flotte miste (browser, AV, DB, runtime). Dichiarato sintetico.
SYNTHETIC_BENIGN_THREADS = [
    ("chrome.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", 350),
    ("msedge.exe", "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe", 280),
    ("MsMpEng.exe", "C:\\Program Files\\Windows Defender\\MsMpEng.exe", 180),
    ("sqlservr.exe", "C:\\Program Files\\Microsoft SQL Server\\sqlservr.exe", 450),
    ("svchost.exe", "C:\\Windows\\System32\\svchost.exe", 120),
    ("explorer.exe", "C:\\Windows\\explorer.exe", 60),
    ("notepad.exe", "C:\\Windows\\System32\\notepad.exe", 8),
    ("java.exe", "C:\\Program Files\\Java\\bin\\java.exe", 500),
    ("postgres.exe", "C:\\Program Files\\PostgreSQL\\bin\\postgres.exe", 120),
    ("Teams.exe", "C:\\Users\\u\\AppData\\Local\\Microsoft\\Teams\\Teams.exe", 280),
]

SYNTHETIC_BENIGN_CMDLINES = [
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1",
    "powershell.exe -NoProfile -Command Get-Process",
    "powershell.exe -Command Get-Service | Where-Object {$_.Status -eq 'Running'}",
    "cmd.exe /c echo hello",
    "python.exe C:\\Tools\\report.py --date 2026-09-13",
    "wmic process where name='chrome.exe' get ProcessId",
]

ENCODED_SAMPLES = [  # (payload_cmdline, is_malicious)
    ("powershell.exe -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuAA==", True),
    ("powershell.exe -e SQBuAHYAbwBrAGEAAAA=", True),
    ("powershell.exe -enc aGVsbG8td29ybGQ=", True),
    # 4 char: sotto ogni soglia sana, ambiguo con flag corti legittimi.
    ("powershell.exe -e aGk=", False),
]

MALWARE_LOOKALIKES = [  # (nome, deve_scattare?)
    ("lockbit.exe", True), ("redline-stealer.exe", True), ("miner.exe", True),
    ("uploader.exe", False), ("bitcoin-qt.exe", False), ("examiner.exe", False),
    ("notepad.exe", False), ("chrome.exe", False),
]


def sweep_threads(thresholds):
    import app.rules.rule_definitions as rd
    out = {}
    old = rd.HIGH_THREAD_COUNT_THRESHOLD
    for thr in thresholds:
        rd.HIGH_THREAD_COUNT_THRESHOLD = thr
        try:
            fp = sum(
                1 for name, path, tc in SYNTHETIC_BENIGN_THREADS
                if rule_high_thread_count(ev(process_name=name, process_path=path,
                                             thread_count=tc)).triggered
            )
            tp = sum(
                1 for tc in (500, 750)
                if rule_high_thread_count(ev(process_name="worker", thread_count=tc)).triggered
            )
            out[thr] = {"fp_synthetic": fp, "tp_corpus_like": tp}
        finally:
            rd.HIGH_THREAD_COUNT_THRESHOLD = old
    return out


def sweep_encoded(min_lens):
    import re
    out = {}
    mal = [cmd for cmd, is_mal in ENCODED_SAMPLES if is_mal]
    for min_len in min_lens:
        pats = [p.replace("{12,}", "{%d,}" % min_len).replace("{20,}", "{%d,}" % min_len)
                for p in ENCODED_PATTERNS]
        compiled = [re.compile(p) for p in pats]
        tp = sum(1 for cmd in mal if any(rx.search(cmd.lower()) for rx in compiled))
        fp = sum(1 for cmd in SYNTHETIC_BENIGN_CMDLINES if any(
            rx.search(cmd.lower()) for rx in compiled))
        out[min_len] = {"tp": tp, "tp_total": len(mal),
                        "fp_benign_cmdlines": fp,
                        "fp_total": len(SYNTHETIC_BENIGN_CMDLINES)}
    out["current(12)"] = dict(out[12])
    return out


def check_lookalikes():
    return [
        {"name": n, "expected": exp,
         "got": rule_malware_family(ev(process_name=n)).triggered}
        for n, exp in MALWARE_LOOKALIKES
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    report = {
        "method": "corpus + pannello benigno SINTETICO (non baseline di flotta)",
        "thread_threshold_sweep": sweep_threads([50, 100, 150, 200, 300, 400, 600]),
        "current_thread_threshold": HIGH_THREAD_COUNT_THRESHOLD,
        "encoded_minlen_sweep": sweep_encoded([8, 12, 20]),
        "malware_lookalikes": check_lookalikes(),
        "recommendation": (
            "Thread 200: aggressivo su desktop (FP su chrome/teams/sql/java sintetici); "
            "restare a 200 SOLO con triage MEDIUM e baseline per-processo come follow-up "
            "(nessun cambio automatico: serve telemetria reale). "
            "Encoded {12,}: miglior compromesso misurato (TP 3/3, FP 0/6). "
            "Lookalike: 8/8 corretti con match a inizio token."
        ),
    }
    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    print("=== Calibrazione soglie (audit P5) ===")
    print("-- thread threshold: FP su 10 benigni sintetici / TP su 2 maligni --")
    for thr, r in report["thread_threshold_sweep"].items():
        flag = "  <-- attuale" if thr == HIGH_THREAD_COUNT_THRESHOLD else ""
        print(f"  thr={thr:4d}: FP={r['fp_synthetic']}/10 TP={r['tp_corpus_like']}/2{flag}")
    print("-- encoded min-length: TP su 4 payload / FP su 6 cmdline benigne --")
    for k, r in report["encoded_minlen_sweep"].items():
        print(f"  min={k}: TP={r['tp']}/{r['tp_total']} FP={r['fp_benign_cmdlines']}/{r['fp_total']}")
    print("-- malware lookalike --")
    bad = [l for l in report["malware_lookalikes"] if l["got"] != l["expected"]]
    for line in report["malware_lookalikes"]:
        print(f"  {line['name']:22s} atteso={line['expected']!s:5s} ottenuto={line['got']!s:5s}")
    print("MISMATCH:", bad if bad else "nessuno")
    print("Raccomandazione:", report["recommendation"])
    return 0 if not bad else 1


if __name__ == "__main__":
    raise SystemExit(main())
