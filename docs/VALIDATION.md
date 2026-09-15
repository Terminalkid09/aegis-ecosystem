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
| SIEM v4: parser, Sigma, correlazione, store, pipeline | **VERDE** (§4.1) |
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
| aegis-brain (con PG+Redis reali) | `pytest tests/` (con `REQUIRE_INTEGRATION=1`) | **533 passed, 0 failed** — gli skipped in questo profilo sono solo i test OS-specifici (non-Windows) |
| aegis-brain (senza integrazione) | `pytest tests/ --ignore=tests/integration` | **390 passed, 16 skipped** (skipped = richiedono PG/Redis reali) |
| aegis-brain — SIEM v4 | `pytest tests/test_ingest_parsers.py tests/test_sigma_engine.py tests/test_correlation_engine.py tests/test_siem_store.py tests/test_siem_pipeline.py` | **VERDE** |
| aegis-brain — API SIEM | `pytest tests/integration/test_siem_ingest.py` | **VERDE** |
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

Nota ambiente: il port-forward Docker di Postgres/Redis è pubblicato solo su
IPv4. Usare `127.0.0.1` (non `localhost`) in `TEST_DATABASE_URL`/`REDIS_URL`:
`localhost` risolve a `::1`, che non è in ascolto, e ogni connessione attende il
fallback IPv4 (~21s) superando il timeout di probe del conftest.

## 3. Cosa coprono (e cosa non coprono) i test

Coperto: logica del motore di detection, pipeline eventi, idempotenza dei
playbook SOAR, RBAC e permessi, cifratura VaultX, PKI/mTLS, hardening della
configurazione, redazione/secret-scan, retention, parsing di Aegis Total,
mapping OCSF, import corpus esterno.

Coperto dal percorso SIEM v4: i **parser multi-sorgente** sono testati uno per
uno su log di formato reale versionati in `tests/corpus/logs/` (syslog RFC3164
+ RFC5424, Windows Event JSON, Zeek `conn/dns/http`, Suricata `eve.json`,
nginx/Squid, Windows Firewall/pfSense/iptables); il **motore Sigma** su
modificatori, condizioni (`and/or/not`, `1 of them`), mapping di campo ed
esclusione esplicita delle feature non supportate; la **correlazione** su
threshold e sequenza; lo **store** su filtro/testo/dedup/ordinamento; la
**pipeline** su evento → detection → alert; il **listener syslog** su
datagrammi UDP e righe TCP reali, dalla porta allo store; la **retention**
SIEM su eventi scaduti e recenti.

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

## 4.1 SIEM v4 — cosa è validato e cosa no

| Area | Stato | Come |
|---|---|---|
| Parser su formati di settore | **VERDE** | corpus versionato `tests/corpus/logs/`, 20 test |
| Motore Sigma (modificatori, condizioni, esclusioni) | **VERDE** | `tests/test_sigma_engine.py`, 34 test |
| Correlazione threshold + sequence | **VERDE** | `tests/test_correlation_engine.py` |
| Store eventi + query/stats + dedup | **VERDE** | `tests/test_siem_store.py` |
| Pipeline ingest → detection → alert | **VERDE** | `tests/test_siem_pipeline.py` |
| API ingest/search end-to-end | **VERDE** | `tests/integration/test_siem_ingest.py` (25 test) |
| **Listener syslog** (UDP + TCP) | **VERDE** | `test_syslog_listener.py` (8) + `tests/integration/test_syslog_listener.py` (3): datagrammi reali sullo store, non chiamate interne |
| Retention degli eventi SIEM | **VERDE** | `tests/integration/test_retention_siem.py` (3) |
| **Log reali dal tuo host** | **NOT-RUN** | collector `scripts/winevent-collector.ps1` pronto: l'output misura la qualità sui *tuoi* Event Log |
| Log reali da Zeek/Suricata/syslog esterni | **NON DISPONIBILE in lab** | i parser sono validati su sample di formato reale; la sorgente non esiste in questo lab |

Nota onesta sul corpus: i log in `tests/corpus/logs/` sono **sample di formato
reale** (stessa struttura prodotta dagli strumenti), non catture di un
incidente reale. Servono a provare che il parser legge il formato e che la
regola scatta; **non** sono una misura di detection su traffico vero — quella
richiede la sorgente, ed è dichiarata come tale.

Per produrre eventi reali dal PC di sviluppo:

```powershell
# Windows Event Log → endpoint di ingestione (richiede un JWT)
pwsh -File scripts/winevent-collector.ps1 -BrainUrl http://localhost:8000 -Token $env:AEGIS_JWT
```

Per la demo end-to-end con tutti i formati (dichiara i sample come sintetici):

```bash
python scripts/siem_demo.py --base-url http://127.0.0.1:8000 --api-key "$AEGIS_API_KEY" --scenario all
```

**Eseguita davvero** il 2026-09-15 su brain locale (PG + Redis reali),
`--scenario all`:

```
[*] scenario=all passi=10 run=c2bce0
[+] [5/10] syslog: stored=1 sigma=1 correlation=1 alerts=2
[+] [7/10] windows_event: stored=9 sigma=6 correlation=0 alerts=6
[+] [8/10] zeek: stored=4 sigma=2 correlation=0 alerts=2
[*] eventi salvati ....... 28      (6 tipi di sorgente)
[*] match Sigma .......... 15
[*] match correlazione ... 2
[*] alert creati ......... 17
```

Verifica di lettura sulle API reali (stesso run): `/ingest/stats` → 28 eventi,
14/14 regole Sigma eseguibili, 5/5 regole di correlazione, distribuzione
`windows_event=9, web=9, syslog=6, zeek=4`, severità `CRITICAL=1, HIGH=10,
MEDIUM=2, LOW=2, INFO=13`; `/search/events?severity=HIGH` → 10 eventi;
`/search/fields` → 24 campi filtrabili; `/telemetry/alerts` → alert con ID
regola Sigma e tecnica MITRE valorizzata (es. `T1543.003`, `T1070.001`,
`T1110`, `T1071.004`).

Questa è l'unica parte della validazione eseguita **end-to-end su servizi
reali**; i sample sono sintetici (dichiarato), l'infrastruttura no.

### Listener syslog — prova su datagrammi reali

Eseguita il 2026-09-15 con il brain avviato con `SYSLOG_ENABLED=true`
(`SYSLOG_BIND=127.0.0.1`, porta 5599) e tre datagrammi UDP inviati da socket:

```
Syslog listener attivo su 127.0.0.1:5599 (udp+tcp)
  → 3 eventi normalizzati (RFC 5424: hostname=fw-test, user=admin, src_ip, event_type=auth_failure)
  → 3 alert [SIGMA 4a8e2c31-…] SSH Authentication Failure, MITRE T1110.001
GET /ingest/sources → syslog: eventi=3, non_riconosciuti=0, ultimo_evento valorizzato
```

Questa prova ha valore aggiunto: è il test che ha smascherato un import errato
che rendeva il listener **non funzionante** pur risultando "in ascolto" (vedi
CHANGELOG). Un listener che apre la porta e non ingerisce è esattamente il
tipo di guasto che una demo senza verifica non rileva.

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
