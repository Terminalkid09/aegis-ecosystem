# OS validation — stato esecuzione

Data report: 2026-09-13.

## Coperto in CI (job `os_compat`, ubuntu-latest + windows-latest)
- Event contract eBPF, replay detection 3 split, NodeTrace unit, Guard unit
  (test OS-specifici skippati fuori piattaforma).
- Preflight: `os-preflight.ps1` 7/7 PASS su host dev Windows (non e' validazione).

## NOT-RUN (richiede macchine dedicate)
| OS | Preflight | Install | Smoke API | 24h telemetria | Stato |
|---|---|---|---|---|---|
| Windows 11 (pulita) | not-run | not-run | not-run | not-run | NOT-RUN |
| Windows Server 2022 | not-run | not-run | not-run | not-run | NOT-RUN |
| Ubuntu 22.04+ (pulita) | not-run | not-run | not-run | not-run | NOT-RUN |
| Debian 12+ | not-run | not-run | not-run | not-run | NOT-RUN |
| RHEL 9+ | not-run | not-run | not-run | not-run | NOT-RUN |

Per `pilot-tested`: 1 run completo documentato su Windows 11 + 1 su Ubuntu 22.04
secondo `README.md`. Per `production-ready`: tutti e 5 gli OS + HA + scala reale.
