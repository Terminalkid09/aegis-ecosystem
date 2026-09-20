# Validazione OS — procedure, checklist, evidenze

Supporto dichiarato (pilot): Windows 11, Windows Server 2022, Ubuntu 22.04+,
Debian 12+, RHEL 9+. Ogni OS richiede: preflight verde + installazione +
smoke E2E (API) + 24h di telemetria senza errori critici.

## 1. Preflight (obbligatorio, read-only)

Windows (PowerShell admin NON richiesta):

```powershell
powershell -ExecutionPolicy Bypass -File scripts/os-preflight.ps1
```

Linux:

```sh
sh scripts/os-preflight.sh
```

Exit 0 = procedere. Exit 1 = risolvere i check `[FAIL]` e ripetere.
Allegare l'output completo al report di validazione.

## 2. Installazione

Seguire `README.md` (profilo base) e `docs/OPERATIONS.md` (profilo
observability). Annotare: commit, data, profilo compose, errori incontrati.

## 3. Checklist post-installazione (ogni OS)

- [ ] `docker compose ps` — tutti i servizi `healthy`
- [ ] `GET /health/ready` = `ready`
- [ ] `GET /health/live` = `alive`
- [ ] `GET /metrics` risponde `200 text/plain`
- [ ] `python scripts/api_smoke.py --base http://localhost:8000` — ALL PASS
- [ ] `python scripts/replay_report.py --all` — F1=1.0 su 3 split
- [ ] Enrollment agent nativo dell'OS riuscito (Guard su Windows, NodeTrace su Linux)
- [ ] 24h telemetria: zero `events_lost_total`, zero errori critici nei log
- [ ] Disinstallazione pulita (nessun residuo: servizi, chiavi, spool)

## 4. Evidenze da conservare

Per ogni OS: output preflight, output smoke, screenshot dashboard, export
`audit_report.json`, log installazione. Vedi `NOT-RUN.md` per lo stato attuale.
