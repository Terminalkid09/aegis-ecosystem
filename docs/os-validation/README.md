# OS validation — procedures, checklist, evidence

Declared support (pilot): Windows 11, Windows Server 2022, Ubuntu 22.04+,
Debian 12+, RHEL 9+. Every OS requires: green preflight + installation + E2E
smoke test (API) + 24h of telemetry with no critical errors.

## 1. Preflight (mandatory, read-only)

Windows (admin PowerShell NOT required):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/os-preflight.ps1
```

Linux:

```sh
sh scripts/os-preflight.sh
```

Exit 0 = proceed. Exit 1 = fix the `[FAIL]` checks and repeat. Attach the full
output to the validation report.

## 2. Installation

Follow `README.md` (base profile) and `docs/OPERATIONS.md` (observability
profile). Record: commit, date, compose profile, errors encountered.

## 3. Post-installation checklist (every OS)

- [ ] `docker compose ps` — all services `healthy`
- [ ] `GET /health/ready` = `ready`
- [ ] `GET /health/live` = `alive`
- [ ] `GET /metrics` returns `200 text/plain`
- [ ] `python scripts/api_smoke.py --base http://localhost:8000` — ALL PASS
- [ ] `python scripts/replay_report.py --all` — F1=1.0 on 3 splits
- [ ] OS-native agent enrollment succeeded (Guard on Windows, NodeTrace on Linux)
- [ ] 24h telemetry: zero `events_lost_total`, zero critical errors in the logs
- [ ] Clean uninstall (nothing left behind: services, keys, spool)

## 4. Evidence to keep

For every OS: preflight output, smoke output, dashboard screenshot,
`audit_report.json` export, installation logs. See `NOT-RUN.md` for the current
status.
