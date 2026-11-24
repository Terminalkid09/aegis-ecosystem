# OS validation — execution status

Report date: 2026-09-13.

## Covered in CI (job `os_compat`, ubuntu-latest + windows-latest)
- eBPF event contract, replay detection on 3 splits, NodeTrace unit tests, Guard
  unit tests (OS-specific tests skipped off-platform).
- Preflight: `os-preflight.ps1` 7/7 PASS on a Windows dev host (not validation).

## NOT-RUN (requires dedicated machines)
| OS | Preflight | Install | API smoke | 24h telemetry | Status |
|---|---|---|---|---|---|
| Windows 11 (clean) | not-run | not-run | not-run | not-run | NOT-RUN |
| Windows Server 2022 | not-run | not-run | not-run | not-run | NOT-RUN |
| Ubuntu 22.04+ (clean) | not-run | not-run | not-run | not-run | NOT-RUN |
| Debian 12+ | not-run | not-run | not-run | not-run | NOT-RUN |
| RHEL 9+ | not-run | not-run | not-run | not-run | NOT-RUN |

For `pilot-tested`: 1 documented full run on Windows 11 + 1 on Ubuntu 22.04
according to `README.md`. For `production-ready`: all 5 OSes + HA + real scale.
