# Detection quality baseline — Aegis 4.3

Generated: `2026-11-19T10:06:12.455552+00:00`

> Synthetic, reproducible baseline. This is **not** a production FP/FN rate: the
> events are constructed and no malware is executed. The 5.0 comparison must use
> the same set and the same command.

## Metrics

| Metric | Value |
|---|---:|
| Malicious cases | 14 |
| Benign cases | 14 |
| True positives | 14 |
| False negatives | 0 |
| False positives | 5 |
| True negatives | 9 |
| Precision | 0.737 |
| Recall | 1.000 |
| F1 | 0.848 |
| False positive rate | 0.357 |

## Cases

| ID | Group | Expected | Detected | Severity | Rules |
|---|---|---|---|---|---|
| `mal-office-powershell` | malicious | yes | yes | CRITICAL | AEGIS-S002, AEGIS-S007, AEGIS-S009, AEGIS-S012 |
| `mal-encoded-only` | malicious | yes | yes | HIGH | AEGIS-S007, AEGIS-S009, AEGIS-S012 |
| `mal-certutil-download` | malicious | yes | yes | HIGH | AEGIS-S012 |
| `mal-renamed-mimikatz` | malicious | yes | yes | CRITICAL | AEGIS-S001, AEGIS-S004, AEGIS-S015 |
| `mal-chrome-svchost` | malicious | yes | yes | HIGH | AEGIS-S002 |
| `mal-thread-201` | malicious | yes | yes | MEDIUM | AEGIS-S013 |
| `mal-thread-300` | malicious | yes | yes | MEDIUM | AEGIS-S013 |
| `mal-dll-side-load` | malicious | yes | yes | HIGH | AEGIS-S011 |
| `mal-run-key` | malicious | yes | yes | HIGH | AEGIS-S016 |
| `mal-schtasks-encoded` | malicious | yes | yes | CRITICAL | AEGIS-S012, AEGIS-S017 |
| `mal-system-powershell` | malicious | yes | yes | CRITICAL | AEGIS-S002, AEGIS-S009 |
| `mal-double-extension` | malicious | yes | yes | HIGH | AEGIS-S004, AEGIS-S006 |
| `hard-rundll32-javascript` | malicious | yes | yes | MEDIUM | AEGIS-S002, AEGIS-S009 |
| `hard-mshta-url` | malicious | yes | yes | HIGH | AEGIS-S009, AEGIS-S012 |
| `benign-chrome` | benign | no | no | NONE | — |
| `benign-powershell-getchilditem` | benign | no | yes | MEDIUM | AEGIS-S002, AEGIS-S009 |
| `benign-cmd-dir` | benign | no | yes | MEDIUM | AEGIS-S002, AEGIS-S009 |
| `benign-python-print` | benign | no | yes | MEDIUM | AEGIS-S009 |
| `benign-certutil-hash` | benign | no | no | NONE | — |
| `benign-rundll32-printui` | benign | no | yes | MEDIUM | AEGIS-S009 |
| `benign-svchost-empty-path` | benign | no | no | NONE | — |
| `benign-explorer-chrome` | benign | no | no | NONE | — |
| `benign-whoami` | benign | no | no | NONE | — |
| `benign-reg-query` | benign | no | no | NONE | — |
| `benign-schtasks-query` | benign | no | no | NONE | — |
| `benign-edge-renderer` | benign | no | no | NONE | — |
| `benign-notepad-temp` | benign | no | no | NONE | — |
| `benign-signed-installer` | benign | no | yes | LOW | AEGIS-S004 |

## Thread threshold

| Threads | Detected | Severity |
|---:|---|---|
| 180 | no | NONE |
| 200 | no | NONE |
| 201 | yes | MEDIUM |
| 300 | yes | MEDIUM |

## Honest reading

- The benign false positives are almost all interpreters (`powershell`, `cmd`,
  `python`) and a signed installer in Downloads: these are low/medium alerts, not
  automatic incidents.
- The `hard-*` cases measure techniques the current rules can miss; they are the
  part to improve in 5.0, not a coverage promise.
- The thread threshold tests the rule, not the sensor: `thread_count` is
  populated by the collector, but it is simulated here.

## Use for the 5.0 comparison

- Freeze the set: do not add or remove cases from the 4.3 file, or the
  comparison loses meaning. New cases belong in a separate set.
- In this panel: **14 TP, 0 FN, 5 FP, 9 TN**. The 5 FPs are three interpreters
  (`powershell`, `cmd`, `python`), `rundll32 printui`, and a signed installer in
  Downloads: they are low/medium alerts, not incidents.
- `recall=1.000` is not a promise: it says this panel contains no technique that
  the current rules miss. The real rate must be measured on real hosts and
  traffic.
- 5.0 must reuse the same command and the same set, and declare whether the
  engine or the rules changed.

## Next step — AP-127

- This file is the frozen baseline for the 4.3 → 5.0 comparison.
- AP-127 (post-4.3) adds a benign corpus of administrative tools with unusual
  arguments, measuring FP/FN per host/day without hiding regressions. It is not
  a production promise.

Repeat with:

```bash
PYTHONPATH=aegis-brain .venv315/Scripts/python.exe scripts/detection_quality.py
```
