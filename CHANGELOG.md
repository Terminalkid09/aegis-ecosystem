# Changelog — Aegis XDR

## Unreleased — Hardening & feature (audit post-v3, pre-pilot)

### Bug corretti
- **Purge giornaliera mai eseguita (P0)**: `retention_scheduler` e la
  riconciliazione revoche all'avvio importavano `async_session_factory`, che
  **non esiste** (il nome reale è `AsyncSessionLocal`). L'errore finiva in un
  `except` generico: nessun crash, nessun log, e la purge di telemetria,
  alert, syslog e audit **non è mai partita**. Correggere l'import è una
  riga; il costo era un database che cresce senza limite.
- **Listener syslog non funzionante (P0)**: stesso import errato nel consumer,
  quindi il listener si apriva sulla porta ma non ingeriva nulla. Ora è
  verificato end-to-end (3 datagrammi UDP → 3 eventi normalizzati → 3 alert
  Sigma con MITRE T1110.001).
- **Retention SIEM non collegata**: `siem_store.purge_expired` era
  implementato e mai chiamato; ora è nel job di retention (DROP delle
  partizioni scadute, DELETE bounded se la tabella è piatta) e il preview
  dichiara anche `siem_events`, che prima riportava 0.
- **Task in background che muoiono in silenzio**: il consumer del listener
  ora ha un done-callback che logga a livello error e marca il listener non
  attivo, invece di lasciare "nessun evento arrivato, nessun log".
- **`.gitignore` escludeva le fixture dei test** (`logs/`, `*.log`): i sample
  dei parser non erano versionati, quindi i test passavano solo in locale.
- **SOAR runaway (P0)**: i playbook si rieseguivano ogni 60s su alert vecchi
  (top-5 dell'agente), ripetendo `isolate_host`/`kill`/`eradicate` all'infinito.
  Ora: esecuzione solo su alert **nuovi** + idempotency key `(playbook_id,
  alert_id)` in Redis, fail-closed se lo store è giù. Cooldown per-agente
  mantenuto come anti-burst esplicito.
- **Batch ingestion**: una riga in errore lasciava la sessione in
  pending-rollback e faceva fallire l'intero batch dell'agente. Aggiunto
  `rollback()` per-evento + validazione età per evento.
- **Aegis Total (formati)**: la UI prometteva formati che il backend rifiutava
  o ignorava (`.pe`, Office, PDF, Mach-O, archivi). Ora ogni famiglia ha un
  parser dedicato e nessuna estensione viene rifiutata.
- **Elenchi di accettazione**: nuovi formati + endpoint `/total/formats`
  (fonte unica di verità per la UI).
- **Timestamp syslog nel 1900 (P0)**: RFC3164 non porta l'anno e
  `parse_timestamp` usava `datetime.strptime`, che in assenza di anno mette
  **1900**. Conseguenza: ogni evento da firewall/switch/NAS/appliance — cioè la
  sorgente che `syslog.py` stessa dichiara come primaria per un SIEM — finiva
  nel 1900. Non era visibile in nessuna ricerca a finestra temporale (la pagina
  *Log Search* risultava vuota), veniva eliminato subito dalla retention e non
  entrava in nessuna finestra di correlazione. Ora l'anno si aggancia al
  riferimento, con rollover di fine anno e senza toccare i formati che l'anno
  ce l'hanno.
- **MITRE: nome della tecnica sbagliato e tattica assente**: gli alert Sigma
  scrivevano in `mitre_technique_name` il **titolo della regola**, quindi la UI
  mostrava `T1110.001 SSH Authentication Failure` dove il nome della tecnica è
  "Password Guessing"; `mitre_tactic_id`/`mitre_tactic_name` restavano vuoti
  anche con il tag `attack.credential_access` presente nella regola. Aggiunta
  la tabella condivisa `app/rules/mitre.py` (tattiche + nomi delle tecniche
  referenziate dalle regole in bundle; una tecnica sconosciuta resta senza nome
  invece di essere indovinata) e i tag delle regole ora viaggiano anche su
  `CorrelationMatch`, così l'alert di correlazione porta la sua tattica.
- **Nessun percorso per ottenere il ruolo privilegiato (P1)**: la matrice
  `ROLE_PERMISSIONS` era applicata in una decina di endpoint, ma nulla — né API
  né UI — poteva assegnare `admin`/`analyst`/`responder`: il database non aveva
  **nessun** admin, e anche l'utente `admin@aegis.com` era ruolo `user`. Così
  isolamento host, approvazione deploy, cancellazione regole/alert e
  assegnazione site rispondevano sempre 403. Aggiunta `python -m app.admin`
  (`list`, `set-role`, `create-user`): **fuori** dal processo HTTP, con audit e
  rifiuto di togliere l'ultimo admin. Un privilegio si concede da una shell,
  non da un'API esposta.
- **`windows_event` rifiutava ciò che `can_parse` rivendicava**: un record con
  chiave `EventID` (per `_MARKERS` e `_parse_record` sono supportati) veniva
  scartato con "no Windows Event record found". Un payload dichiarato leggibile
  e poi rifiutato.
- **Aegis-Guard non partiva (P0 di packaging, tre cause)**: (1) `build.bat`
  costruiva il runtime minimo con `jlink` senza il modulo **`jdk.net`**, che
  Apache HttpClient 5 richiede (`jdk.net.Sockets`): il JRE risultava corretto e
  l'agente moriva con `NoClassDefFoundError`; (2) `install.ps1` installava il
  servizio con la stringa `"java"` letterale invece del percorso risolto, e non
  verificava la **versione**: con una `java` 8 nel `PATH` il servizio partiva e
  moriva con `UnsupportedClassVersionError`; (3) lo stesso script impostava solo
  `AEGIS_GATEWAY_URL`/`AEGIS_AGENT_ID`/`AEGIS_SCAN_INTERVAL_MS`, mai
  `AEGIS_ENROLL_KEY` (che `Config.ENROLL_KEY` legge con `getEnvOrThrow`, quindi
  fatale all'avvio) né `AEGIS_BRAIN_URL`. Verificato end-to-end su Windows 11:
  enrollment, emissione identità device via CSR, process monitor attivo, eventi
  consegnati con HTTP 200.
- **Estrazione del JRE portatile incompleta**: l'installer spostava solo `bin/`
  dalla distribuzione scaricata, producendo un runtime che non parte
  (`could not open ...\lib\jvm.cfg`). Ora si sposta l'intera distribuzione.
- **Test dipendenti dal calendario**: `tests/integration/test_siem_ingest.py`
  interrogava la ricerca con `hours=24` su un corpus con timestamp **fissi**
  (2026-09-15T12:00). Il giorno dopo quattro test fallivano senza che nulla
  fosse rotto — un falso negativo che arriva esattamente quando si esegue la
  suite prima di una release. La finestra ora si calcola dai timestamp del
  corpus, entro il massimo accettato dall'API.
- **Suite di test che poteva cancellare il database di sviluppo**: `conftest.py`
  si fidava di `TEST_DATABASE_URL` senza controllare il nome del database, e i
  test eseguono `drop_all`/`create_all`. Ora un database che non contenga
  "test" nel nome viene rifiutato con un messaggio esplicito
  (`ALLOW_NON_TEST_DB=1` è l'unico override).

- **Collector Windows Event Log: nessun evento inviato (tre bug distinti, tutti
  silenziosi)**: il collector era l'unico componente dello scope v4 **mai
  eseguito su log reali**. Al primo utilizzo serio sono emersi tre difetti:
  1. **`Get-WinEvent` con troppi ID restituisce zero eventi senza errore**: la
     lista completa di `$InterestingIds` (24 ID) non produce nulla su System,
     mentre un sottoinsieme di 22 produce i 201 eventi attesi. Il collector
     dichiarava "0 eventi" su un canale che ne aveva 201. Ora la query si fa a
     blocchi da 16 e i risultati si uniscono per `RecordId`.
  2. **Corpo troncato da PowerShell 5.1**: il body JSON era passato a
     `Invoke-RestMethod` come *stringa*, e PS 5.1 calcola `Content-Length` dal
     numero di caratteri. Un messaggio di Windows con accenti (2470 caratteri,
     2479 byte) veniva troncato e il brain rispondeva `There was an error
     parsing the body`. Su qualunque Windows non inglese l'invio era
     impossibile. Ora il corpo è inviato come byte UTF-8.
  3. **Bookmark avanzato prima dell'invio**: lo stato per canale veniva scritto
     *prima* di sapere se l'invio era riuscito, quindi un 4xx/5xx marcava gli
     eventi come "già inviati" e la passata successiva non li ritrovava più:
     perdita definitiva. Ora il bookmark si aggiorna solo dopo un invio
     riuscito, e `-DryRun` non lo tocca affatto (prima la passata di prova
     "consumava" gli eventi senza inviarli).
  Verificato end-to-end sul PC di sviluppo: 10 eventi `7045` reali →
  `stored=10` in `siem_events`, con timestamp corretti e accenti preservati.

### Test e verifica
- **`scripts/api_smoke.py` esteso da 3 a 17 controlli**: oltre a
  `/health/live`, `/health/ready` e `/metrics`, ora esegue uno sweep
  **autenticato** sul percorso reale: login → catalogo parser → copertura
  detection → ingestione di un log syslog vero → evento normalizzato e
  ricercabile con `src_ip` estratto → alert Sigma con tecnica MITRE →
  idempotenza dell'`event_id` → 422 con diagnosi su payload non riconosciuto →
  coerenza del RBAC col ruolo dichiarato. Senza credenziali il livello
  autenticato **non viene saltato in silenzio**: l'uscita è 2 con il motivo
  (`--public-only` è la scelta esplicita per il run incompleto).

### Sicurezza
- **Rate limiter**: storage Redis (`RATE_LIMIT_STORAGE_URI`) e `key_func`
  basata su `X-Forwarded-For` solo dietro proxy fidato (header spoofabile non
  azzera più il budget).
- **OSINT**: lookup live ora richiede JWT (era anonimo e innescava traffico
  verso API esterne).
- **Discovery**: RBAC `deploy` su scan/reputation/host-manual/sync/scan-via-agent;
  scan di rete non più disponibile a un semplice viewer.
- **Deploy**: rimossi fisicamente i percorsi con credenziali VaultX `#deploy-creds`
  (WinRM/SSH); `/discovery/deploy` risponde 410, unico percorso = token firmato.
- **Rules**: allowlist dei campi PATCH (mass-assignment) e cache di dizionari
  serializzati (niente istanze ORM detached).
- **CSP**: Content-Security-Policy aggiunta in Caddy sulla dashboard.
- **Guard/Link**: validazione IP/dominio comandi agent, ack dei comandi e
  logging del thread comandi; coda Redis FIFO.

### Feature
- **OCSF 1.4.0 export** (`/api/v1/ocsf/*`): alert → Detection Finding (2004),
  telemetria → Process Activity (1007), JSON o NDJSON, con severità, ATT&CK
  `attacks[]` e `unmapped.aegis`. Aggancio SIEM senza parser custom
  (`app/services/ocsf.py`, `schema_description`, `/ocsf/convert`).
- **Import corpus esterno** (`POST /rules/replay/import`): carica fino a 3
  JSONL (benign/suspicious/malformed) e li scora col motore reale; `expect`
  per riga alimenta il recall. Cap 32 MB / 50k righe.
- **`docs/VALIDATION.md`**: stato di validazione riproducibile (cosa gira,
  cosa è NOT-RUN, cosa manca per production-ready).

- **SIEM v4 — ingestion multi-sorgente** (`app/ingest/`): parser registry
  con auto-detection e 12 parser nominati (`windows_event`, `zeek`,
  `suricata`, `pfsense`/`pfirewall`/`iptables`, `squid`/`nginx`, `syslog`
  RFC3164+5424, `json`). Ogni sorgente mappa su un evento unificato
  OCSF-aligned. Endpoint `POST /ingest/{source}` (+ `/ingest/test` dry-run,
  `/ingest/catalog`, `/ingest/sources`, `/ingest/stats`) e listener syslog
  UDP/TCP (`SYSLOG_ENABLED`, bind `127.0.0.1` di default).
- **SIEM v4 — motore Sigma** (`app/rules/sigma/`): YAML → regole eseguibili con
  mapping campi, modificatori (`contains/startswith/endswith/re/cidr/base64/…`)
  e condizioni (`and/or/not`, `1 of them`, `all of them`). Le feature non
  supportate **escludono** la regola e lo dichiarano (`/ingest/detection-coverage`)
invece di eseguirla a metà. Bundle di 14 regole reali (Windows Event, Linux
  auth, Zeek DNS, Suricata, proxy/firewall) con MITRE ATT&CK.
- **SIEM v4 — correlazione multi-evento** (`app/services/correlation.py`):
  finestre Redis per `threshold` (N in T) e `sequence` (A poi B); le detection
  entrano nella stessa pipeline alert/playbook degli agenti.
- **SIEM v4 — store e ricerca**: tabella eventi partizionata per mese, dedup su
  `event_id`, `POST/GET /search/events` (filtri su allowlist + testo escapato),
  `/search/fields`, `/search/stats`.
- **Windows Event Log collector** (`scripts/winevent-collector.ps1`): log reali
  dal PC di sviluppo (parametri configurabili, `wevtutil` → `/ingest`).
- **Demo SIEM** (`scripts/siem_demo.py`): sample nei formati di settore con
  scenari (bruteforce, Windows persistence, DNS tunneling, web attack) e
  `--dry-run`. Dichiarati sintetici in `docs/VALIDATION.md`.
- **Frontend**: pagine *Log Sources* (sorgenti, EPS, health, catalogo parser,
  dry-run, copertura detection) e *Log Search* (filtri, tabella, dettaglio,
  paginazione).
- **`docs/V4_SCOPE.md`**: scope chiuso della v4 con definizione di "fatto".

### Test
- Nuovi: `test_playbook_idempotency` (5), `test_ocsf` (7),
  `test_total_formats` (9), `test_corpus_import` (6),
  `test_ingest_parsers` (20), `test_sigma_engine` (34),
  `test_correlation_engine` (15), `test_siem_store` (11),
  `test_siem_pipeline` (11), `test_syslog_listener` (8),
  `tests/integration/test_siem_ingest` (25),
  `tests/integration/test_syslog_listener` (3),
  `tests/integration/test_retention_siem` (3),
  `MainCommandValidationTest` (5, Java).
  Suite completa: brain **533 passed / 0 failed** (con PG+Redis reali),
  guard 123, link 17, NodeTrace 70, contratto eBPF ALL PASS.

## Unreleased — Audit F1–F10 (dataset indipendenti, metriche, health, supply-chain, E2E)

- Detection: split `training`/`validation`/`regression` indipendenti (`corpus-v2`),
  manifest sha256, gate `test_dataset_splits.py`; `POST /rules/replay` accetta `split`;
  `scripts/generate_corpus_splits.py` con auto-verifica contro le regole.
- Metriche: HELP+TYPE unici per famiglia, escaping label, `normalize_path_label`
  (cardinalità), float non-finiti sicuri; path HTTP normalizzato in `/metrics`.
- Health: `/health/live` solo prova di vita; `/health/ready` stato completo;
  optional estesi (ollama, grafana, prometheus, osint); dashboard usa `/health/ready`.
- Supply-chain: `.trivyignore` con metadati per gruppo + test di struttura/scadenza;
  `scripts/gen_sbom.py` (CycloneDX manifest-derived, 68 componenti).
- Update agent: protezione anti-rollback in `UpdateManager.stagePackage` + 5 test
  (downgrade, stessa versione, upgrade/latest, download troncato, canonicalizzazione).
- Benchmark: metadati riproducibilità, p50/p95/p99 ingestion, reconnect seedato, `--json`.
- OS validation: `scripts/os-preflight.{ps1,sh}` + checklist in `docs/os-validation/`
  (stato: NOT-RUN, nessuna macchina dedicata disponibile).
- E2E: spec Playwright (`frontend/e2e/smoke.spec.ts`, 3 passati + 1 skippato senza credenziali)
  + `scripts/api_smoke.py` (ALL PASS su stack live).
- Fix: `scripts/test-installers.ps1` (Join-Path PS 5.1) — ora ALL PASS.

## Unreleased — F1–F10: osservabilità, qualità, detection, replay, dashboard, ops (branch dev)

### F1 Osservabilità
- `/metrics` Prometheus su aegis-brain (`aegis_http_requests_total`,
  `aegis_http_request_seconds`, `aegis_events_*`, latenza ingestion, queue depth).
- `health/live` esteso con check `pipeline`, `pki`, `mtls`; log con `service`.
- Rate limit per agente (`APP_EVENTS_PER_MIN`) + limiti body-size per path.
- Profilo Compose `observability` (Prometheus+Grafana, credenziali da env,
  bound 127.0.0.1); installers `lab --observability`.

### F2 Qualità telemetria
- Redazione automatica segreti in `/report` e `/report/batch` pre-persistenza.
- `EventSchema.seq` ora `>= 0`; middleware body-size; test edge/invalidi.

### F5 Detection engineering
- Regole statiche con `exceptions`/`allowlist` e catalogo `RULE_NOTES`
  esposti da `/rules/static`.

### F6 Replay & dataset
- Dataset versionato `corpus-v1` (benign/suspicious/malformed), replay con seed
  deterministico, `scripts/replay_report.py` (precision/recall/F1, FP/host-day).

### F7 Dashboard
- Pipeline health strip in DashboardOverview (db/redis/pipeline/pki/mtls) da
  `/health/live`.

### F8/F9 Deployment & security
- `install.sh/install.ps1` profilo observability; matrice profili in README.
- Immagini non-root: brain `USER aegis` + dirs volumi nell'immagine
  (trivy AVD-DS-0002 risolto); link Boot 3.5.16 + pin netty/tomcat/jackson
  (29 CVE risolte); guard pin httpcore5 5.4.3 (2 CVE); `.trivyignore`
  documentato per i residui senza fix upstream; `apt/apk upgrade` al build time.
- Migrazione `0011_revoked_certs` ora idempotente (IF NOT EXISTS): il riavvio
  post-audit non crasha più.

## Unreleased — Gap-closing mTLS nativo + supply chain (branch dev)

### Agent mTLS nativo (testato live contro stack reale, MTLS required)
- Guard Java: `DeviceIdentity` (EC locale, CSR, PEM 600, quarantena), `DeviceTls` (TLS 1.3 + CA pinnata, mai trust-all), bootstrap/rinnovo in `Main`, header `X-Client-Cert`, guida revoca throttled, enroll-key mai più loggata.
- NodeTrace: `services/device_identity.py`, bootstrap/rinnovo nel loop, header su tutte le chiamate, supporto cert in urllib+curl (+`--cacert`), guida revoca.
- Rotte legacy `/register|/update|/heartbeat|/commands` applicano lo stesso mTLS (gap bypass chiuso); re-enroll di revocati -> 403 anche via compat.
- Live: Guard e NodeTrace con enroll->CSR->heartbeat/report 200, rinnovo con stesso id, CA errata 401, revoca 401 + no-wipe + no-crash, re-enroll 403 (13 + 12 check verdi).

### Supply chain a zero HIGH/CRITICAL (Trivy fs: 5 manifest puliti)
- Guard: httpclient 5.3.1->5.5.2, BouncyCastle 1.81->1.81.1.
- Link: Spring Boot 3.3.5->3.5.12 (compilava solo dopo: Lombok vecchio rotto su JDK25); riparati 5 test mai eseguiti prima + nuovo `ApiKeyFilterTest`; handler 400 per header assenti.
- CI: `npm audit --audit-level=high`, Trivy fs (exit 1), SHA di tutte le action riverificati (trovato e corretto upload/download scambiati + trivy inventato).

### Produzione
- `ENTERPRISE_STRICT` (prod overlay): rifiuto avvio senza `MTLS_MODE=required`.
- Audit `exclude_test=true` (verificato live: 49 righe test nascoste, 31 reali intatte).
- Migrazione pwdlib verificata (hash legacy -> rehash al login, test dedicato).

## Unreleased — Enterprise roadmap M0–M10 (branch dev)

### M0 Baseline e threat model
- `docs/THREAT_MODEL.md` v1.0 (asset, ruoli reali, boundary, 17 gruppi API, 14 scenari), `docs/RISK_MATRIX.md` (R1–R18 con owner/priorità), `docs/OS_COMPATIBILITY.md` (Win11/Server22-25, Win10 lab, Ubuntu 22.04/24.04, Debian 12, RHEL 9, niente Android).
- Retention configurabile: telemetria 14, alert 90, audit 365, syslog 30 giorni (`RETENTION_*_DAYS`).

### M1 Schema eventi v2 e pipeline
- Contratto v2 backward-compat (`schema_version/event_id/boot_id/seq`, tempi doppi, `proc_start_ns`, rete strutturata, provenance/quality); `check-contract.py` 16 controlli ALL PASS.
- Guard: spool cifrato AES-256-GCM su disco + replay ordinato, buffer bound 2000, contatori `stats()`, fallback legacy solo su 404/405/501, retry con jitter.
- Brain: dedup `event_id` + `SeqTracker` gap/reset, contatori in `/stats` e nei batch.
- `docs/EVENT_SCHEMA_V2.md` (compat, offline, overhead, residui).

### M2 Sensore Windows
- Normalizzazione path/cmdline, anti-PID-reuse via `GetProcessTimes` (v2 `procStartNs`), ingest ETW con feature-flag mai-crashing, snapshot persistenze read-only (Run keys + Startup), provenance/quality esplicite, fallback CIM per WMIC.

### M3 Sensore Linux
- Probe kernel (FULL/PARTIAL/ABSENT) loggata all'avvio, parser auditd mirato (solo exec) con tailer opt-in, starttime da `/proc` (v2), provenance `ebpf-full`, unit systemd `aegis-nodetrace.service`.

### M4 Detection
- 15 regole con `rule_id` AEGIS-S001…S015 + versione + confidence separata; canary log-only via `RULE_CANARY_IDS`; audit su create/patch/delete regole custom.
- Replay deterministico + corpus versionato (12 benigni/12 sospetti, P/R/F1 = 1.0) + `POST /rules/replay`; MTTD solo live.

### M5 Correlazione e IR
- Finestre configurabili (`CORR_*`), raggruppamento per similarità in auto-group, note analyst in audit, playbook dry-run (`POST /soar/playbooks/{id}/dry-run`) con matrice rischio/approvatore/rollback, isolate/release anche al responder.

### M6 Enrollment e deploy
- PKI device: CA locale, firma CSR (CN=agent_id), revoche persistenti, `POST /enroll/csr`, `GET /enroll/ca.crt`, `POST /enroll/agents/{id}/revoke`.
- Manifest artefatti Ed25519 (interop Python→JVM testata) + HMAC compat; server-pinning su entrambi gli agent; installer senza segreti (test).

### M7 Dashboard e organizzazione
- Matrice 6 ruoli (viewer…admin, estensione senza restrizioni esistenti), siti via meta + filtro + assign, stato online/stale/offline, contatori salute in stats, statement purge retention, API client frontend per i nuovi endpoint.

### M8 Produzione on-premise
- Overlay prod con log rotation, `BACKUP_PASSPHRASE` nel servizio backup, `scripts/restore-db.sh` e `scripts/purge-retention.sh` (doppia conferma), `docs/OPERATIONS.md` (install/backup/restore/upgrade/rollback/PKI/purge/health).

### M10 CI e supply chain
- CI: trigger anche su `dev`, job contract (schema + secret-scan + NodeTrace), unit test Guard in CI, job supply-chain (pip-audit + SBOM) allegata alla release.

### Limiti residui onesti
- mTLS enforcement TLS e driver firmato fuori scope; dedup server in memoria; viewer/auditor read-only completo sugli endpoint legacy da hardening dedicato; digest-pin immagini e CVE-SLA operativi in pilot; PG/Redis singoli.

## Unreleased — Hardening finale pre-pilot (verificato su Docker reale)

### Dipendenze (47 vulnerabilità -> 0, `pip-audit` pulito)
- PyJWT 2.10.1->2.14.0, cryptography 44.0.2->50.0.1, python-dotenv 1.0.1->1.2.3, fastapi 0.115.5->0.141.1 + starlette 0.41.3->1.6.0, pytest 8.3.3->9.1.1 + pytest-asyncio 0.24->1.4.0, argon2-cffi 21.3.0->23.1.0 (risolve conflitto resolver), python-multipart 0.0.32 (richiesto da Starlette 1.x).
- python-jose RIMOSSO (CVE senza fix + API rotta in 3.5; token legacy HS256 verificati da PyJWT).
- conftest modernizzato per pytest-asyncio 1.x (loop di sessione via `asyncio_default_*_loop_scope`, niente fixture custom).
- Catena Alembic riparata (`0007` puntava a revision inesistente; fail-closed aveva bloccato correttamente l'avvio).

### mTLS verificato end-to-end su Docker
- `MTLS_MODE=required` + bootstrap `/enroll/csr` senza cert; trasporto cert DER-base64 + fingerprint legato in `Agent.meta`; `Caddyfile.mtls` + overlay `docker-compose.mtls.yml` (:8443 `require_and_verify`, :443 invariata).
- Provato live: handshake senza cert rifiutato, cert CA sbagliata rifiutata (`unknown_ca`), heartbeat via :8443 200, revoca nega sul wire 401, :443 intatta.
- Trovato e corretto durante l'e2e: volumi `!reset` azzerati, `header_up` fuori da `reverse_proxy`, placeholder hash inesistente (-> DER verificato), secret PEM multilinea non trasportabile, entrypoint senza permessi volumi.

### Backup autenticati e restore reali
- GPG simmetrico AES256+MDC ovunque (niente CBC nudo; `openssl enc` AEAD assente nei build minimali); restore via file temporaneo (niente plaintext parziale in caso di tamper).
- DB: dump+GPG+restore su DB di prova con conteggi identici (22/20/19), tamper rifiutato prima di psql. PKI: roundtrip byte-identico + tamper/guardie negative.
- `BACKUP_PASSPHRASE` fail-fast in prod (provato con/senza).

### Produzione
- Entrypoint brain root->chown volumi->`gosu aegis` (PKI scrivibile, server mai root); `.dockerignore` (niente `.env` nell'immagine, verificato); volumi `pki_data`/`artifact_data`; immagini e action pinnate per digest/SHA.
- Suite finale: brain 224/224 su PG/Redis reali, Guard 72/72, NodeTrace 36/36, contract ALL PASS, frontend build OK, click-through 23/23 widget.

## 3.0.0 — Enterprise SOC release

### Sensori kernel (fuori dal polling)
- Linux: sensore eBPF (`aegis-ebpf/`) — tracepoint exec + kprobe exit, ringbuf, verificato su kernel 6.6 (`EBPF_TEST_PASS`, parent chain reale).
- Windows: consumer ETW Kernel-Process (`aegis_etw.c`, compila pulito, richiede lab admin).
- Contratto unico `event.schema.json` + golden sample reale + `check-contract.py`.
- Guard: `ExternalEventIngester` (pipe JSON → SystemEvent), `ISOLATE_HOST`/`DEISOLATE_HOST` reali via firewall, `UPDATE_AGENT` OTA firmata HMAC + staged, ack ok/failed al SOC, versione in heartbeat.
- NodeTrace: `UPDATE_AGENT` + ack + versione/capabilities + forward stream eBPF opt-in.
- Brain: tracking `agents.isolated`, `agent_version`, `capabilities`; ack endpoint; artifact firmati serviti all'agente.

### SOC commerciale
- Incidenti: raggruppamento alert, status, assignee, timeline (API + UI).
- MITRE ATT&CK coverage matrix (static + custom rules).
- Process tree forense per alert.
- Isolate/Release operativi da UI con audit (admin/analyst).
- Aegis Total: upload file/ZIP, code viewer con redaction, anti-crack policy, delete GDPR, disclaimer + audit.

### Deploy moderno
- Token monouso one-liner, job massivi con stato, OTA firmata, artifact store.
- Deploy legacy con password in chiaro deprecato e rimosso dalla UI.

### Hardening
- RBAC bulk alerts (admin/analyst), playbook `script` solo admin, FIFO code comandi,
  resilienza Redis (niente più 500 a cascata), demo disabilitata in prod,
  auth moderna PyJWT/pwdlib con fallback, axios 1.12+.

### Limiti dichiarati (non-enterprise ancora)
- Sensori user-mode per remediation; niente driver firmato / tamper protection.
- Firma OTA simmetrica (HMAC), non PKI. TLS agente non verificato su NodeTrace.
- macOS solo polling (serve entitlement Apple). ETW da validare in lab admin.
- Single Postgres/Redis, `uvicorn --workers 1`, backup non cifrato.
