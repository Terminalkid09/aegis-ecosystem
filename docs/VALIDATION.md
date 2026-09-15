# Validazione Aegis — cosa è stato eseguito e cosa no

Data report: 2026-09-15. Sostituisce la domanda "è production-ready?"
con un elenco verificabile di cosa gira, cosa è verde e cosa manca.

Regola di questo documento: **nessun numero senza comando riproducibile**.
Se un valore non è stato misurato qui, è marcato NOT-RUN.

## 1. Stato attuale

Classificazione: **pilot-ready lab** (non production-ready — vedi §5).

| Area | Stato |
|---|---|
| Unit/integration suite (tutti i componenti) | **VERDE** |
| Detection replay su 3 split indipendenti | **VERDE** (P/R/F1 1.0 su corpus sintetico) |
| Contratto eventi eBPF ↔ agent | **VERDE** |
| Build frontend + typecheck | **VERDE** |
| Bandit / flake8 (critical) | **VERDE** |
| Validazione su OS puliti (Win 11 / Server / Ubuntu / Debian / RHEL) | **NOT-RUN** |
| Validazione su corpus pubblico esterno | **NON ESEGUITA** (endpoint pronto, §4) |
| HA, scala 1000 host, 90gg crescita DB | **STIMA** (`docs/BENCHMARK.md`) |

## 2. Suite eseguite (misurate)

Tutte eseguite su host di sviluppo (Windows 11, Python 3.10, JDK 25),
2026-09-15, working tree corrente.

| Componente | Comando | Risultato |
|---|---|---|
| aegis-brain | `pytest tests/` | **301 passed, 102 skipped** (skipped = test che richiedono PG/Redis reali e OS non-Windows) |
| aegis-brain (senza integrazione) | `pytest tests/ --ignore=tests/integration` | **279 passed, 14 skipped** |
| aegis-guard | `mvn -o test` | **123 passed, 0 failed** |
| aegis-link | `mvn -o test` | **17 passed, 0 failed** |
| NodeTrace | `pytest` in `NodeTrace/agents/python` | **70 passed, 2 skipped** |
| Contratto eBPF | `python aegis-ebpf/check-contract.py` | **ALL PASS** (16 controlli) |
| Replay detection | `python scripts/replay_report.py --all` | training/validation/regression **P/R/F1 1.0**, FP/host-day 0.0 |
| Frontend build | `npm run build` | OK (tsc + vite) |
| Bandit | `bandit -r app/ -ll` | 0 medium/high |
| Flake8 (critical) | `flake8 app/ ... --select=E9,F63,F7,F82` | 0 errori |

I numeri di replay valgono **solo** per il corpus sintetico versionato
(`corpus-v2`). Vedi §4 per come ottenere numeri su dati reali.

## 3. Cosa coprono (e cosa non coprono) i test

Coperto: logica del motore di detection, pipeline eventi, idempotenza dei
playbook SOAR, RBAC e permessi, cifratura VaultX, PKI/mTLS, hardening della
configurazione, redazione/secret-scan, retention, parsing di Aegis Total,
mapping OCSF, import corpus esterno.

**Non** coperto dalle unit test: comportamento reale su kernel senza BTF,
firewall Windows/Linux sotto carico, outbound bloccato da proxy aziendali,
AV/EDR di terze parti che interferiscono col driver eBPF, upgrade in-place
del DB su dati di produzione.

## 4. Validazione su corpus esterno (feature nuova)

Il replay interno misura il motore su un corpus scritto mentre le regole
venivano sviluppate. Per un numero che un cliente possa **riprodurre**, il
motore ora accetta dati esterni:

```bash
# API (richiede JWT): invia fino a 3 file JSONL
curl -X POST https://<brain>/api/v1/rules/replay/import \
  -H "Authorization: Bearer $TOKEN" \
  -F benign=@benign.jsonl \
  -F suspicious=@suspicious.jsonl \
  -F malformed=@malformed.jsonl \
  -F host_days=30
```

Formato `suspicious.jsonl` (una riga = un evento, campo prodotto da Aegis):

```json
{"event_type":"PROCESS_CREATED","process_name":"mimikatz.exe","pid":20,
 "process_path":"C:\\temp\\mimikatz.exe","expect":["AEGIS-S004","AEGIS-S009"]}
```

- `expect` elenca le regole attese per quella riga → alimenta il **recall**.
- Riga senza `expect` → è solo input: misura i **falsi positivi**, non il recall.
- `malformed.jsonl` accetta righe rotte: devono diventare `invalid`, non crash.

Limiti di sicurezza: ≤32 MB per file, ≤50.000 righe. Il motore è lo stesso
del replay interno (`static-replay-v1`), quindi i risultati sono confrontabili.

Fonti esterne suggerite: Atomic Red Team (mappatura exec → evento Aegis),
log convertiti da EVTX/Auditd, dataset di ricerca con licenza compatibile.
**Attenzione licenza**: verificare i termini prima di importare dati di terzi.

## 5. Cosa manca per "production-ready"

In ordine di blocco:

1. **Validazione su OS puliti** — 1 run completo documentato (install → smoke →
   24h telemetria) su Windows 11 e Ubuntu 22.04 aggiorna
   `docs/os-validation/NOT-RUN.md`. È la condizione per "pilot-tested".
2. **Corpus esterno** — un report in questo file con la provenienza del
   dataset e P/R/F1 reali, dichiarando i limiti.
3. **Scala e HA misurati** — oggi sono stime (`ARCH_REVIEW.md`).
4. **Upgrade/rollback DB** provato su dati non vuoti.
5. **Penetration test indipendente** su API e agent (non solo
   gli unit test di sicurezza già presenti).

Fino a (1)+(2) la dicitura corretta resta **advanced prototype / pilot-ready**,
come già in `docs/os-validation/NOT-RUN.md`.

## 6. Comandi di riproduzione (TL;DR)

```bash
pytest aegis-brain/tests/ -q
cd aegis-guard && mvn -o test
cd aegis-link && mvn -o test
cd NodeTrace/agents/python && pytest -q
python aegis-ebpf/check-contract.py
python scripts/replay_report.py --all
python scripts/audit_report.py            # JSON macchina + report umano
cd frontend && npm run build && npm run lint
```
