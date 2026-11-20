# AEGIS ECOSYSTEM + KRAKEN — specifica di lavoro (handoff)

**Versione documento:** 2.8 — 2026-11-17 (v2.8: agente unico Go in 4.3.0, response intelligence in 4.4.0; la sezione 4.3.0 sotto è storica)
**Destinatario:** sessione di sviluppo successiva (umana o agente)
**Decisione 2026-11-17 — agente unico:** Guard e NodeTrace confluiscono in
un solo agente Go nella 4.3.0; la response intelligence passa alla 4.4.0.
`aegis-link` resta Spring Boot. La specifica eseguibile aggiornata è
`docs/archive/PLAN_V4.2.md` §Fase 3-4; la sezione 4.4.0 sotto descrive la response
storica e i suoi numeri 4.4.x non sono più numeri di release.
**Repo Aegis:** `Terminalkid09/aegis-ecosystem`, branch `dev` @ `ea57f08` (codice identico a `c9831c5`; dopo `c9831c5` solo commit documentali. `main` @ `38e245f`)
**Repo Kraken:** `Terminalkid09/Kraken`, branch `main` locale @ `7fd50a9` (1 commit avanti a `origin/main` @ `d86c8d5`, **non pushato**). Il fix di avvio KRAKEN-SEC-000 è già in `7fd50a9`; su `origin/main` il servizio non parte ancora.
**Report di analisi precedente:** `docs/archive/ANALISI_AEGIS_KRAKEN_v4.md` (analisi del 2026-11-08; questo documento è la specifica operativa aggiornata)

**Aggiornamento requisiti (v2.1, vincolante):**
- **Kraken è e resta un microservizio separato** (`services/kraken`): processo, DB, migrazioni, rete, credenziali e UI propri. **Mai fuso nel Brain** (niente logica, tabelle, socket o privilegi di Kraken nel Brain). Il Brain è piano di controllo/detection; Kraken è servizio di deception e lab.
- **Kraken Lab:** piattaforma/lab configurabile per simulare sottoreti, host e scenari d’attacco riproducibili e verificare il comportamento di Aegis end-to-end (rilevato/non rilevato, correlazione, incidente, risposta) in modalità shadow → attiva, con raccolta evidenze.
- **UI dedicate e distinte:** Kraken ha una **UI propria** per dati/operazioni sue (sensori/nodi, sessioni, comandi, sample, campagne, topologia e run del lab, configurazione). La SPA Aegis mostra la vista unificata/correlata (eventi, alert, incidenti, timeline, esito detection/risposta) senza sostituire la UI Kraken.

**Correzioni v2.2 (verificate il 2026-11-13, sostituiscono le affermazioni precedenti):**
- **Licenza (D1, chiusa):** Aegis adotta **AGPL-3.0-only** per il codice, `NOTICE` per l'attribuzione e una policy separata per nome/logo. Non è open core, non è proprietaria e non ha restrizioni d'uso aggiuntive: la restrizione è il copyleft di rete dell'AGPL. La v2.1 assumeva Apache-2.0: era falsa, e senza licenza il default era «tutti i diritti riservati».
- **Kraken SEC-000:** il blocker di avvio è già corretto nel commit locale `7fd50a9` (`__allow_unmapped__ = True`); il documento v2.1 misurava `origin/main` `d86c8d5`. Gate A diventa «pushare, importare, verificare», non «applicare una riga».
- **KRAKEN-SEC-005:** la password in chiaro finisce in DB (`credential_attempts.password`) e negli export CSV/JSON/PDF. **Non** viene inviata a Telegram (il messaggio legge solo sensor/IP/paese/utente/sessione) né scritta nel JSONL SIEM (che non include username/password). Il finding resta High per DB ed export, ma la portata è ridotta.
- **Outbox Kraken→Aegis:** una sola implementazione, in **Postgres** (tabella `outbox`, transazionale con l'ingest). La v2.1 diceva Redis in §5.3 e tabella in §9.2: contraddizione risolta.
- **Sample:** Aegis conserva **solo metadati** (`sha256`, tipo, YARA, IOC, `kraken_sample_id`); nessun `storage_path` e nessun file malware nel perimetro Aegis. I file restano nel volume cifrato di Kraken.
- **Test Kraken:** 103 funzioni di test (non 108); su `7fd50a9` sono **58 passed / 7 failed** e i 7 fallimenti scrivono in `/app` (KRAKEN-LOGIC-005).
- **Frontend:** 18 viste nella `PAGE_MAP` di `App.tsx` + login (19 schermate), non 19 viste SOC + login.
- **Stime:** Gate B 41–45 h (5–6 gg), Gate C 56–60 h (7–7,5 gg), Gate D 9–10 gg, Gate 0 4–6 gg. La 4.1.0 con la verticale Kraken completa non è «9–13 giornate» ma **27–28 giornate di lavoro netto** (~9 settimane a 30 h). Roadmap realistica: **37–43 settimane a 40 h/settimana**, 49–55 a 30 h. Vedi §6 e §10.1.
- **Retention sample:** KRAKEN-OPS-003 passa alla 4.1.0 (è un requisito legale, non una feature della 4.2).
- **Release Aegis:** il job `release` pubblica **solo** il jar di Guard. Brain, frontend, Link, NodeTrace, compose, SBOM e checksum non sono artefatti di release: AEGIS-REL-002.

**Decisioni v2.3 (2026-11-13, chiudono D1–D16; D16 aggiornata in v2.4):**
- **D1 — Licenza:** AGPL-3.0-only + `NOTICE` + `TRADEMARK.md`; SPDX nei file nuovi, niente EULA/CLA finché il titolare è minorenne e senza struttura legale.
- **D2 — Target:** mid-market e ambienti grandi; Windows/Linux ora, macOS 5.x, router OpenWrt 4.3 lab, sensori di rete 4.2; Android/iOS non prima della 5.x e solo via MDM.
- **D3/D4 — Go-to-market:** visibilità open-source e community, non vendita diretta; niente billing, niente listino, sponsorship solo dopo trazione.
- **D5/D10 — Deployment:** Docker Compose è il deployment supportato della 4.x; architettura K8s-ready da subito; Helm opzionale in 5.1, non prima.
- **D6 — Monorepo:** Aegis resta alla root, Kraken entra in `services/kraken`; il move in `aegis/` è un refactor separato e solo dopo Gate A. Nessun subtree/push senza autorizzazione esplicita.
- **D7 — Playbook:** rimozione totale dell'azione `script` in 4.1; catalogo di azioni nominate in 4.3.
- **D8 — Feature 4.2:** nessuna priorità: si esegue l'ordine del piano.
- **D9 — Lab:** obiettivo cyber range completo, consegnato in tre fasi (Lab shadow 4.2 → regressione 4.3 → range multi-host 5.0), non in una release.
- **D11 — Kafka:** solo oltre le soglie, con Redpanda/NATS prima; nessun Kafka cerimoniale.
- **D12 — AI:** Ollama locale di default, cloud opt-in con chiave del cliente; mai AI nel contenimento.
- **D13 — Multi-tenancy:** un deployment per cliente nella 4.x, `tenant_id` predisposto nello schema; multi-tenant solo per MSSP in 5.0.
- **D14 — Compliance:** ISO 27001 dopo la 4.1, con DPA e registro trattamenti subito; niente SOC 2 o ACN senza partner.
- **D15 — Posizionamento:** flank mid-market con SOC-in-a-box + deception/Lab; nessun nome di vendor o prodotto usato come benchmark compare in codice, doc, commit o marketing.
- **D16 — Capacità e orizzonte:** sviluppatore singolo, 30 h/settimana sostenibili; progetto **portfolio-first**, senza data fissa. Con la verticale Kraken completa la 4.1 è ~9 settimane di lavoro netto e la roadmap 49–55 settimane è una stima, non una scadenza. 40 h solo in vacanza; nessuna compressione delle stime.
- **D17 — Perimetro 4.1:** la 4.1 non è una release “Kraken avviabile”. È la release in cui la **verticale Kraken è completa e utilizzabile**: servizio nel compose, contratto firmato con outbox/retry, UI Kraken raggiungibile, vista Aegis in sola lettura, smoke test end-to-end. L'espansione (nuovi sensori, campagne, Lab, timeline, ATT&CK) resta alla 4.2+. Il cambiamento sposta lavoro tra release, non riduce il totale: le stime di §10 vanno ricalcolate, non copiate.

---

## 0. Come usare questo documento

Questa non è una lista di idee: è un piano eseguibile. Ogni voce ha un ID, un file o un'area di intervento, un criterio di accettazione e un test. Le regole per chi lavora:

1. **Non chiudere una voce senza il suo test.** Se un test non può esistere, va scritto perché nel campo "Verifica".
2. **Non riordinare a piacere le sezioni 6 e 10.** L'ordine è per dipendenza: i fix bloccanti di Kraken precedono qualunque integrazione, perché il servizio deve partire e i suoi test devono essere verdi prima di qualunque contratto.
3. **Ogni PR tocca una cosa.** Un finding = una PR, con test di regressione che fallisce prima e passa dopo.
4. **Le misure si rifanno, non si citano.** I numeri in §1 sono del 2026-11-12: vanno riprodotti con i comandi in §11.1 prima di dichiarare "fatto".
5. **Niente feature prima dei fix bloccanti.** La 4.1.0 ha un cancello: §6.1 verde.
6. **Nessuna release pubblica senza Gate 0.** Licenza, `SECURITY.md`, artefatti completi e note di upgrade precedono il tag: un prodotto senza licenza non è distribuibile, per quanto il codice sia buono.
7. **Le stime si contano a ore, non a ottimismo.** Ogni voce ha un effort; il totale si somma e si aggiunge un buffer del 20%. Le date in §10 sono conseguenza, non promessa.
8. **Niente commit o push senza autorizzazione esplicita.** Il subtree (`git subtree add`) crea un commit: vale la stessa regola.
9. **Commit per tipo, non per accumulo:** `feat:`, `fix:`, `docs:`, `test:`, `chore:`. Niente nomi di vendor/prodotti usati come benchmark interno, niente co-autore, niente attribuzione ad AI.

Legenda severità: **Critical** = compromissione host o bypass di autenticazione; **High** = takeover di agente, perdita/alterazione di dati, CI rossa su security gate; **Medium** = DoS, privacy, isolamento parziale; **Low** = igiene, incoerenza, osservabilità.
Legenda stato: **V** verificato in questa analisi, **D** documentato, **I** ipotesi, **R** raccomandazione.

---

## 1. Stato verificato al 2026-11-12

### 1.1 Ambiente usato per i test

| Pezzo | Versione / note |
|---|---|
| Python | 3.15.2, venv dedicata, dipendenze da `aegis-brain/requirements.txt` |
| PostgreSQL | 16 (binari portabili `pgserver`), DB `aegis_test`, `aegis_migrate`, `krakendb` |
| Redis | 7 (`redislite`), porta 6379 |
| Java | Temurin 21.0.13 + Maven 3.9.9 (userland) |
| Node | 26.13.0 / npm 11.20.0 |
| Docker | CLI 29.1.3 + compose 2.40.3, **nessun daemon** (compose solo `config`, niente `up`) |

### 1.2 Risultati misurati

| Area | Comando | Esito |
|---|---|---|
| Brain, senza DB | `pytest -q` | **572 passed, 210 skipped, 5 failed** (7,7 s) |
| Brain, con PG+Redis | `REQUIRE_INTEGRATION=1 pytest -q` | **785 passed, 2 failed** (37,6 s) |
| Brain, schema da zero | `alembic upgrade head` ×2 | **36 tabelle**, head `0019`, seconda run idempotente |
| Brain, API | `app.openapi()` | **131 path, 153 operazioni**, 24 famiglie |
| Brain, detection | `replay_report.py --all` | 21 regole; TP/FP/FN = 16/0/0 (validation), 7/0/0 (regression), training ok; F1 1.0 |
| Brain, Sigma | `get_engine().coverage()` | 14 regole, **14 eseguibili, 0 escluse**, 14 tecniche MITRE |
| Brain, correlazione | `get_correlation_engine().coverage()` | 5 regole, 5 eseguibili, 6 tecniche |
| Brain, SAST | `bandit -r app -ll` | **0 Medium, 0 High** (63 Low) |
| Brain, SCA | `pip-audit -r requirements.txt` | **7 vulnerabilità** (PyJWT 2.14.0 ×2 → 2.15.0; pymongo 4.9.2 ×5 → 4.18.3) |
| Guard | `mvn -B test` | **136 test, 0 failure**, BUILD SUCCESS |
| Link | `mvn -B test` | **17 test, 0 failure**, BUILD SUCCESS |
| eBPF | `check-contract.py` | **RESULT: ALL PASS** (v1, v2, ETW, seq senza boot_id rifiutata) |
| Frontend, lint | `npm run lint` | **0 errori**, 25 warning |
| Frontend, tipi | `tsc -b --noEmit` | exit 0 |
| Frontend, build | `npm run build` | OK in 1,03 s; chunk principale 682 kB (202 kB gzip) |
| Frontend, SCA | `npm audit --audit-level=high` | **3 high** (vite, launch-editor) |
| Aegis, compose | `docker compose config` | valido con env fittizio |
| Kraken, import | `python -c "import app.main"` | **OK su `7fd50a9`**; **FALLISCE** su `origin/main` `d86c8d5` (`ArgumentError` su `AttackEvent.commands`) |
| Kraken, migrazioni | `alembic upgrade head` | **6 tabelle** su `7fd50a9`; fallisce su `d86c8d5` |
| Kraken, test | `pytest tests/unit` | **58 passed / 7 failed** su `7fd50a9` (i 7 scrivono in `/app`); collection error su `d86c8d5` |
| Kraken, dopo fix 1 riga (v2.1) | alembic + pytest | 6 tabelle, 58 passed / 7 failed — misura storica, oggi superata da `7fd50a9` |
| Kraken, runtime | uvicorn + curl | health 200; **register `is_admin:true` → admin**; `/containers/active` e `/export/csv` 200; ingest senza chiave 403 |
| Kraken, SAST | `bandit -r app honeypot -ll` | 0 High, **7 Medium**, 6 Low |
| Kraken, SCA | `pip-audit -r requirements.txt` | **30+ advisory** su 5 pacchetti |

### 1.3 Le cinque conclusioni che governano il piano

1. **Aegis è un prodotto**: 489 file, 61.789 LOC, 131 endpoint, 787 test raccolti, 36 tabelle, migrazioni riproducibili, 0 finding High da bandit, hardening superiore alla media open source.
2. **Kraken è un prototipo**: su `origin/main` non si avvia; il commit locale `7fd50a9` lo fa partire, ma non è pushato e 7 test falliscono. Finché il commit non è remoto, nessuna delle sue affermazioni è verificabile da terzi.
3. **La CI di Aegis oggi è rossa** su tre fronti: `pip-audit` (7), `npm audit` (3 high), 2 test dipendenti dal calendario. `main` era verde al merge, non lo è più.
4. **`dev` e `main` non divergono**: `git diff HEAD origin/main` è vuoto. Lavorare su `dev` non introduce differenze di contenuto.
5. **L'integrazione ha senso solo dopo i fix**: portare un servizio che non parte dentro un monorepo che passa i test sposta il problema, non lo risolve.

---

## 2. Inventario Aegis

### 2.1 Numeri

| Voce | Valore |
|---|---|
| File tracciati | 489 |
| LOC totali (py/java/ts/tsx/sh/yml) | 61.789 |
| Python | 239 file (~19k LOC in `aegis-brain/app`) |
| Java | 68 file (Guard 53, Link 15, test inclusi) |
| TypeScript/React | 36 file (SPA Vite) |
| Migrazioni Alembic | 19 (0001 → 0019) |
| Tabelle risultanti | 36 (32 ORM + 4 di servizio) |
| Endpoint HTTP | 131 path / 153 operazioni |
| WebSocket | 2 (`/ws/overview`, `/ws/alerts`) |
| Test | 787 raccolti (Brain) + 136 (Guard) + 17 (Link) |
| Docs | README 45 KB + 11 file in `docs/` |
| Compose | base + 4 overlay (prod, mtls, ha, observability) |

### 2.2 Componenti e responsabilità

| Componente | Tecnologia | Cosa fa | Cosa **non** fa |
|---|---|---|---|
| `aegis-brain` | FastAPI, SQLAlchemy async, Alembic, Redis | API, auth, RBAC, audit, detection, correlazione, incidenti, playbook, PKI, deploy, AI, SIEM, Total | nessuna sandbox dinamica, nessun supporto multi-tenant, 1 worker |
| `aegis-link` | Spring Boot 3 | accetta eventi endpoint e li accoda su Redis `aegis:events` | nessun parsing, nessuna detection |
| `aegis-guard` | Java 25 | process monitor, FIM, YARA, ETW/eBPF ingest, remediation, OTA | Linux remediation parziale (vedi AEGIS-SEC-007) |
| `NodeTrace` | Python stdlib + curl | telemetria periodica, eBPF/auditd, scan di rete, heartbeat | nessuna remediation (by design: telemetry-only) |
| `aegis-ebpf` | C/CO-RE | collector exec, contratto eventi golden | solo Linux, opt-in |
| `frontend` | React 19, Vite, Zustand, react-query | 18 viste SOC + login (19 schermate) | nessuna controparte mobile |
| `Caddy` | Caddy 2 | TLS, CSP dashboard, proxy `/api` e `/ws` | nessun WAF |

### 2.3 Pipeline eventi (verificata)

```
agente → POST /telemetry/report[/batch]  (Bearer device secret + mTLS opzionale)
        → dedup event_id (Redis LRU + fallback memoria)
        → SeqTracker (gap/reset/late per agent+boot)
        → telemetry_service: persistenza + alert
        → detection_context (Sigma 14 regole + euristica + correlazione 5 regole)
        → alert → incident_grouping → playbook_engine → Redis aegis:commands:<agent>
        → agente: GET /commands/batch → esegue → POST /commands/ack

shipper → POST /ingest/{source} (X-Api-Key) → registry parser (7) → UnifiedEvent
        → siem_events (partizionata per mese) → Sigma → alert
```

Punti di rottura noti: coda comandi limitata a 100 elementi (`ltrim`), revoca agente fail-open su errore DB, `script` come shell sul server.

### 2.4 Matrice superfici agenti (D2)

| Superficie | Stato 4.x | Come | Limite dichiarato |
|---|---|---|---|
| Windows PC/server | supportato | Guard Java + ETW, servizio NSSM, one-liner/MSI | serve admin; niente driver kernel, ETW user-mode |
| Linux PC/server | supportato | Guard + NodeTrace + eBPF (opt-in) o auditd | eBPF richiede kernel ≥5.8 e privilegi; auditd è fallback |
| macOS | lab only | NodeTrace polling; nessun EndpointSecurity | 5.x: serve Apple Developer Program, entitlement EndpointSecurity, notarization e MDM |
| Android | escluso 4.x | 5.x companion via Android Enterprise/MDM | niente telemetria processuale; solo segnali app/VPN/accessibility, con limiti Play |
| iOS/iPadOS | escluso | 5.x solo MDM/Network Extension | sandbox totale, niente monitoraggio processi, App Store |
| Router reti piccole | 4.3 lab | agente statico Go/Rust su OpenWrt (arm/mips), config firmata, export syslog/NetFlow | solo OpenWrt supportato; RAM/flash limitate; niente DPI o container; è per reti piccole, non per il core |
| Reti grandi / server | 4.2 | syslog/NetFlow/IPFIX/SNMP + sensore Zeek/Suricata su mirror/SPAN o TAP | sensore passivo, non inline; niente agente su switch/firmware chiusi; serve un punto di mirror |
| Container/K8s | 5.1 | DaemonSet eBPF, niente socket | richiede privilegi e kernel compatibile; Helm solo 5.1 |

**Agente vs sensore di rete (D2).** Un **agente** è software installato sull'host: vede processi, file, utenti e può eseguire azioni (kill, quarantine), ma consuma CPU/RAM e richiede un OS supportato. Un **sensore di rete** non sta sullo switch: riceve una copia del traffico da una porta mirror/SPAN o da un TAP e produce eventi — Zeek per connessioni/DNS/HTTP/TLS, Suricata per firme IDS. Non vede processi o file: vede chi parla con chi, su quale porta e con quale frequenza; il payload solo se non è cifrato. È **passivo**, non blocca il traffico: il contenimento resta su agente o firewall. I due si completano: l'agente dice "il processo X ha aperto la connessione", il sensore dice "quella connessione ha contattato un C2 noto".

**Perché non un agente su ogni switch.** Molti apparati hanno firmware chiuso, RAM/flash limitate e nessun runtime: installarci sopra qualcosa significa rischiare un outage di rete e una catena di update che non controlli. Si esportano invece syslog, NetFlow/IPFIX e SNMP verso Aegis, e si mette un sensore dove c'è un punto di mirror (core/distribuzione). Su reti piccole il router OpenWrt può fare da agente/collector (4.3 lab); su reti grandi il sensore è un server dedicato o una VM, non un agente per apparato.

**Regola:** un agente per superficie, stesso contratto eventi e stesso enrollment; nessuna superficie è "supportata" senza test su OS reale e limite scritto. Android/iOS non entrano nella 4.x: sarebbero una promessa che non possiamo mantenere da soli.

### 2.5 Cosa è dichiarato e non c'è

| Dichiarazione | Realtà |
|---|---|
| Deploy SSH/WinRM massivo | **rimosso**: `POST /deploy/jobs` risponde 501 se `method != oneline` (`deploy.py:407`) |
| HA multi-nodo | overlay di 39 righe e consumer in-process: dichiarato più che provato |
| mTLS di default | implementato, ma `MTLS_MODE=off` è il default |
| Copertura MITRE ampia | 14 tecniche su ~200: buona base Windows/persistence, debole su credential access, lateral movement, C2, exfil |
| Sandbox file | assente: Aegis Total è statica |

---

## 3. Inventario Kraken

### 3.1 Numeri e stato

| Voce | Valore |
|---|---|
| LOC Python | 4.054 (app 2.078 + honeypot 505 + test) |
| Test | 103 funzioni, 65 unit; **58 passed / 7 failed** su `7fd50a9` (i 7 scrivono in `/app`) |
| Migrazioni | 2 → 6 tabelle |
| Servizi compose | 9 + 3 volumi |
| CI | solo `.gitlab-ci.yml`; workflow GitHub rimosso in `d86c8d5` |
| Auth | JWT HS256 access 15 min, refresh 7 giorni, cookie `SameSite=Strict`, `HttpOnly`, `Secure` fuori da DEBUG |
| Sensori | SSH (asyncssh), HTTP, FTP, Telnet |
| Sandbox | container Alpine via Docker SDK, 128 MB, 64 PID, `cap_drop ALL` |
| Coverage dichiarata | 54% |

### 3.2 Cosa fa davvero

Honeypot multi-protocollo che accetta ogni credenziale, registra i comandi, li esegue in un container sandbox, arricchisce con GeoIP, salva in PostgreSQL, notifica Telegram, scrive un JSONL SIEM, mostra dashboard Jinja e produce export CSV/JSON/PDF.

### 3.3 Difetti strutturali (prima dei finding)

1. **Su `origin/main` non si avvia** (import models, KRAKEN-SEC-000); il commit locale `7fd50a9` contiene già il fix, ma non è pushato.
2. **Il modello di isolamento è invertito**: la sandbox ha rete Internet (per scelta, vedi `scripts/secure_sandbox.sh` che *permette* 80/443) mentre l'app ha il Docker socket. È l'opposto di ciò che serve: l'app non deve poter parlare col daemon, la sandbox non deve poter parlare col mondo.
3. **L'autenticazione è decorativa**: register pubblico con ruolo scelto dal client, refresh non revocabile, logout solo sull'access.
4. **La privacy non è progettata**: password in chiaro, backup non cifrati, malware in tar non cifrato.

---
## 4. Registro completo dei finding

Formato: ID · severità · confidence · file:riga · impatto · fix · test · release.
I finding **AEGIS-SEC-002**, **AEGIS-REL-001** e **KRAKEN-SEC-001/002/003** bloccano la release. KRAKEN-SEC-000 è già risolto in `7fd50a9`; va verificato e pushato, non rifatto.

### 4.1 Aegis — sicurezza

#### AEGIS-SEC-001 — Re-enroll senza prova di possesso dell'host
- **Severità:** High · **Confidence:** Alta · **File:** `aegis-brain/app/api/v1/enroll.py:76-107`
- **Evidenza:** se esiste un `Agent` con stesso `hostname`+`os_type`, il codice genera `new_secret` e lo scrive in `existing.device_token_hash`. Nessuna prova che il chiamante sia lo stesso host; l'unico stop è la revoca.
- **Impatto:** con la enroll key statica (distribuita a ogni install) si ottiene un secret valido per l'`agent_id` di un endpoint reale: si leggono i comandi di remediation (kill, isolate, quarantine), si invia telemetria falsa per quell'host. Con `MTLS_MODE=off` non c'è certificato a fermarlo.
- **Fix:** legare l'identità a `machine-id`/TPM/instance-id; re-enroll solo con token single-use emesso per quell'host; audit come `re-enrollment sospetto` + notifica; rotazione della chiave statica.
- **Test:** due enroll con stesso hostname/os → il secondo deve fallire senza token dedicato; con token dedicato deve funzionare e produrre audit.
- **Release:** 4.1.0 (bloccante)

#### AEGIS-SEC-002 — Una chiave per due mestieri: enroll e firma OTA
- **Severità:** High · **Confidence:** Alta · **File:** `aegis-brain/app/api/v1/deploy.py` (installer, `build_manifest`/`sign_manifest_bundle`), `NodeTrace/.../updater.py`, `aegis-guard/.../UpdateManager.java`
- **Evidenza:** l'installer scriveva `AEGIS_ENROLL_KEY=$ENROLL_TOKEN` nell'env del servizio; il Brain firmava con `settings.AGENT_ENROLL_KEY` (statica); l'agente verificava con `Config.ENROLL_KEY` (il token). Due chiavi diverse per lo stesso controllo.
- **Impatto:** (a) gli agenti installati via one-liner rifiutano ogni update legittimo (OTA rotta in silenzio); (b) chi conosce la enroll key statica può firmare qualunque digest.
- **Fix:** tre chiavi separate (enroll, firma manifest, device secret); Ed25519 obbligatorio in ogni profilo; HMAC OTA rimosso in 4.1.0; token di enroll in file 0600, mai nell'env persistente.
- **Test:** agente installato con token riceve update Ed25519 firmato → applicato; HMAC con chiave diversa → rifiutato.
- **Release:** 4.1.0 (bloccante)

#### AEGIS-SEC-003 — Playbook `script`: comando arbitrario sul Brain
- **Severità:** Medium · **Confidence:** Alta · **File:** `aegis-brain/app/services/playbook_engine.py:280-300`
- **Evidenza:** `subprocess.run(target.split(), timeout=min(120))`; doppio gate (flag `PLAYBOOK_SCRIPT_ENABLED=false` + ruolo admin).
- **Impatto:** da admin di piattaforma a root del server che custodisce PKI, audit e credenziali di tutti gli agenti.
- **Fix:** rimuovere l'azione e sostituirla con catalogo di azioni nominate; se deve restare, eseguire in container effimero senza rete e senza volumi.
- **Test:** `script` → `blocked` con flag off; nessun path che raggiunga `subprocess` (grep test).
- **Release:** 4.4.0 (rimozione), 4.1.0 se resta (hardening)

#### AEGIS-SEC-004 — Decompressione non limitata in Aegis Total
- **Severità:** Medium (DoS) · **Confidence:** Alta · **File:** `aegis-brain/app/api/v1/total.py:913-918`
- **Evidenza:** `gzip.decompress(raw)` / `bz2` / `lzma` sul payload grezzo fino a `TOTAL_MAX_ZIP_MB` (200 MB). Il cap per-entry (64 MB) è applicato dopo, sul risultato già in RAM.
- **Impatto:** una bomba 1:1000 esaurisce la memoria; il Brain gira a un worker → SOC offline.
- **Fix:** `zlib.decompressobj(..., max_length)` incrementale, cap progressivo, rifiuto oltre N× il dichiarato, analisi in worker separato con `RLIMIT_AS`.
- **Test:** payload 1:1000 oltre il cap → 422 senza superare il limite di memoria (misurare RSS).
- **Release:** 4.1.0

#### AEGIS-SEC-005 — Rate limit in memoria e IP del proxy
- **Severità:** Medium · **Confidence:** Alta · **File:** `aegis-brain/app/core/config.py` (blocco rate limiting), `app/core/rate_limit.py`
- **Evidenza:** `RATE_LIMIT_STORAGE_URI=None` → storage in-process; `RATE_LIMIT_TRUST_FORWARDED_FOR=False` → dietro Caddy tutti gli IP sono il proxy. Il warning è loggato all'avvio.
- **Impatto:** il limite login (10/min) diventa globale: 10 tentativi bloccano tutti gli operatori (DoS), mentre un attaccante distribuito non è limitato per account (resta il throttle per email).
- **Fix:** nel compose prod `RATE_LIMIT_STORAGE_URI=redis://...` e `RATE_LIMIT_TRUST_FORWARDED_FOR=true`; validazione che rifiuta storage in memoria fuori da DEBUG.
- **Test:** due IP dietro proxy → bucket distinti; Redis down → comportamento dichiarato.
- **Release:** 4.1.0

#### AEGIS-SEC-006 — API key globale unica per l'ingestione
- **Severità:** Medium · **Confidence:** Alta · **File:** `app/core/deps.py:verify_api_key`, `app/api/v1/ingest.py:ingest_auth`
- **Evidenza:** confronto constant-time corretto, ma una sola chiave per Link, shipper e tooling; nessuna revoca per sorgente, nessuno scope.
- **Impatto:** un firewall compromesso può iniettare eventi in **qualsiasi** sorgente e sopprimere i veri alert (avvelenamento SIEM); la rotazione ferma tutte le integrazioni.
- **Fix:** tabella `api_keys(id, name, hash, scopes, source, revoked_at, last_used)`; `X-Api-Key` risolve la chiave e limita la sorgente; rate limit per chiave.
- **Test:** chiave A non scrive sulla sorgente B; revoca immediata senza impatto sulle altre.
- **Release:** 4.1.0

#### AEGIS-SEC-007 — `REMOVE_PERSISTENCE` distruttivo e disonesto
- **Severità:** High · **Confidence:** Alta · **File:** `aegis-guard/src/main/java/com/aegis/guard/Main.java:505` e blocco Linux `:560-575`
- **Evidenza:** `exec("reg","delete", key, "/f","/va")` quando **qualsiasi** voce della chiave contiene il nome del processo: `/va` cancella il valore di default dell'intera chiave Run. Su Linux il ramo else si limita a `removed.add("cron:"+line)` senza modificare nulla, e `processCommand` invia comunque ack `ok`.
- **Impatto:** (a) disponibilità: si perde persistenza legittima su un host di produzione durante un incidente; (b) integrità del SOC: remediation dichiarata applicata e non applicata.
- **Fix:** cancellare il singolo valore (`/v <name>`), mai `/va`; se non si rimuove nulla → `failed/partial`; su Linux implementare la rimozione o dichiarare `unsupported`.
- **Test:** chiave Run con due valori → rimosso solo il matching; Linux → ack ≠ ok finché non c'è rimozione reale.
- **Release:** 4.1.0 (bloccante)

#### AEGIS-SEC-008 — Postura mTLS permissiva
- **Severità:** Medium · **Confidence:** Alta · **File:** `app/core/config.py`, `docker-compose.yml`, `docker-compose.prod.yml`
- **Evidenza:** `MTLS_MODE=off`, `ENTERPRISE_STRICT=false`; il guard `enforce_enterprise_strict` esiste ed è corretto, ma è opt-in.
- **Impatto:** un deploy "pilot" crede di avere identità device e ha solo bearer token; revocare un certificato non ha effetto perché non esiste.
- **Fix:** profili espliciti: `lab` (off), `pilot` (optional + log), `prod` (required + strict); un solo `AEGIS_PROFILE` che deriva i flag.
- **Test:** `AEGIS_PROFILE=prod` con MTLS_MODE=off → il Brain non parte.
- **Release:** 4.1.0

#### AEGIS-SEC-009 — mTLS via header = certificato come credenziale portabile
- **Severità:** Medium · **Confidence:** Media-Alta · **File:** `app/services/mtls.py`
- **Evidenza:** il certificato viaggia in `X-Client-Cert` e viene verificato per catena/CN/revoca. Nessun proof-of-possession: la chiave privata non serve al server.
- **Impatto:** chi legge l'header (log del proxy, dump di memoria, trace) può replayarlo insieme al bearer token. Il "secondo fattore" è una seconda stringa, non un secondo fattore.
- **Fix:** terminare TLS con client auth in Caddy (`Caddyfile.mtls` già presente) e far verificare al Brain solo il fingerprint iniettato dal proxy, con strip degli header client; in alternativa firma di nonce con la chiave device.
- **Test:** header `X-Client-Cert` inviato direttamente al Brain (bypass proxy) → rifiutato.
- **Release:** 4.2.0

#### AEGIS-SEC-011 — Device secret in argv di `curl`
- **Severità:** High · **Confidence:** Alta · **File:** `NodeTrace/agents/python/utils/curl_http.py:84-100`
- **Evidenza:** `_curl_request` passa `-H "Authorization: Bearer <secret>"` e `-H "X-Client-Cert: ..."` come argomenti del processo; `request()` preferisce curl quando esiste. Su Linux `/proc/<pid>/cmdline` è leggibile da ogni utente locale.
- **Impatto:** un utente non privilegiato sulla macchina legge il device secret e impersona l'agente (telemetria falsa, polling dei comandi, ack). È esattamente il segreto che il prodotto esiste per proteggere.
- **Fix:** preferire `urllib` (già implementato) e usare curl solo con `--config` da file 0600 o header da stdin (`-H @-`); oppure rimuovere il ramo curl.
- **Test:** avviare l'agente e verificare che `/proc/<pid>/cmdline` non contenga il token; unit test sul builder di comando.
- **Release:** 4.1.0 (bloccante per ambienti multiutente)

### 4.2 Aegis — logica, affidabilità, osservabilità

| ID | Titolo | Sev | File | Impatto | Fix | Release |
|---|---|---|---|---|---|---|
| AEGIS-LOGIC-001 | `isolate` risponde `agent.isolated` senza aggiornarlo | Low | `api/v1/telemetry.py:786` | UI incoerente col comando accodato | aggiornare stato su ack, non su enqueue | 4.1.0 |
| AEGIS-LOGIC-002 | Idempotenza playbook (playbook, alert) blocca la riesecuzione dopo riapertura | Low | `playbook_engine.py:139` | alert riaperto non riattiva il contenimento entro 24 h | chiave con `revision`, TTL configurabile | 4.2.0 |
| AEGIS-LOGIC-003 | Coda comandi `ltrim 0..99` perde i più vecchi | Medium | `playbook_engine.py:_send_agent_command` | durante un burst i comandi svaniscono senza contatore | coda per priorità + metrica `commands_dropped` | 4.1.0 |
| AEGIS-LOGIC-004 | Revoca agente fail-open su errore DB | Medium | `agent_deps.py` (blocco `RevokedCert`) | con mTLS off un agente revocato continua | fail-closed: 503 su errore, non `pass` | 4.1.0 |
| AEGIS-LOGIC-005 | `queue_depth` legge `aegis:events:pending` ma la coda è `aegis:events` | Low | `app/core/health.py:121` | readiness mostra sempre 0 | usare la chiave vera + `LLEN processing/dlq` | 4.1.0 |
| AEGIS-LOGIC-006 | 2 test SIEM dipendono dal calendario (corpus 2026-09-15, cap 720 h) | High (CI) | `tests/integration/test_siem_ingest.py:37,301` | CI rossa 30 giorni dopo ogni aggiornamento corpus | `freezegun` o corpus generato relativo a `now` | 4.1.0 |
| AEGIS-LOGIC-007 | 5 test falliscono senza DB invece di skippare | Low | `tests/integration/test_retention_siem.py`, `test_syslog_listener.py` | segnale CI ambiguo | usare fixture `db_session` o marker `integration` | 4.1.0 |
| AEGIS-LOGIC-008 | `pymongo`/`motor` dipendenze mai importate | Medium (SCA) | `aegis-brain/requirements.txt` | 5 CVE da codice inutilizzato | rimozione | 4.1.0 |
| AEGIS-LOGIC-009 | PyJWT 2.14.0 con 2 advisory | Medium | `requirements.txt` | gate pip-audit rosso | bump a 2.15.0 + test token legacy | 4.1.0 |
| AEGIS-OPS-001 | Backup: passphrase in env del container | Low | `scripts/backup-db.sh` | visibile in `docker inspect` | secret file 0400 + `--passphrase-file` | 4.2.0 |
| AEGIS-OPS-002 | Nessun test automatico di restore | Medium | `scripts/restore-db.sh` | backup non verificato = backup inesistente | job notturno: restore su DB usa-e-getta + checksum | 4.1.0 |
| AEGIS-OPS-003 | Bundle frontend 682 kB in un chunk | Low | `frontend/vite.config.ts` | first paint lento su rete lenta | `manualChunks` per vendor/pagine | 4.2.0 |
| AEGIS-OPS-004 | 25 warning lint frontend | Low | vari `.tsx` | rumore che nasconde regressioni | `npm run lint -- --fix` + regola su exhaustive-deps | 4.2.0 |
| AEGIS-OPS-005 | Vite con 3 advisory high (dev-only) | Medium (CI) | `frontend/package-lock.json` | `npm audit --audit-level=high` rosso | bump Vite; separare audit dev/prod | 4.1.0 |
| AEGIS-OPS-006 | Discovery usa `create_subprocess_shell("arp -a")` | Low | `api/v1/discovery.py:84,97` | shell non necessaria su percorso privilegiato | `exec` con argv + parsing | 4.2.0 |
| AEGIS-OPS-007 | Stato in-process (dedup, rate limit, cache) e un solo worker | Medium | `app/main.py`, `app/core/rate_limit.py` | `--workers N` rompe dedup e WebSocket; l'HA dichiarata non è provata | stato condiviso su Redis + test di concorrenza; worker multipli dietro Caddy | 4.2.0 |
| AEGIS-OPS-008 | Nessun RBAC per sito/tenant | Medium | `app/services/fleet.py` (`site` in `Agent.meta`) | un analista vede tutti i siti; nessuna tabella Site/Tenant | tabella `sites`, scope su ogni query, ruolo per sito | 5.0.0 (4.4 per il solo filtro) |

#### AEGIS-REL-001 — Nessuna licenza
- **Severità:** High (legale/distribuzione) · **Confidence:** Alta · **File:** radice del repo
- **Evidenza:** `ls LICENSE*` non trova nulla; README e documenti non dichiarano una licenza. Senza licenza il default è «tutti i diritti riservati»: nessuno può legalmente usare, modificare o ridistribuire il codice, e nessun procurement lo approva.
- **Impatto:** blocca distribuzione, contributi esterni, pilot con clienti e qualunque affermazione «open source». La v2.1 assumeva Apache-2.0: era falso.
- **Fix:** scegliere il modello (D1), aggiungere `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md`, intestazioni SPDX nei file nuovi; per un prodotto commerciale, EULA/contratto separato.
- **Test:** check CI che fallisce se `LICENSE` manca; revisione legale prima del tag.
- **Release:** Gate 0 / 4.1.0

#### AEGIS-REL-002 — Release incompleta
- **Severità:** High (prodotto) · **Confidence:** Alta · **File:** `.github/workflows/ci.yml` (job `release`)
- **Evidenza:** il job costruisce e allega solo `aegis-guard.jar` + SBOM. Non pubblica immagini Brain/Link/Frontend, NodeTrace, compose bundle, checksum delle immagini, note di upgrade, CHANGELOG.
- **Impatto:** un cliente non può installare la release con un artefatto versionato; il deploy resta «clona il repo e spera». È incompatibile con un prodotto serio.
- **Fix:** release pipeline che builda e firma (cosign) tutte le immagini, allega `docker-compose.prod.yml`, `.env.example`, SBOM per componente, `SHA256SUMS`, `CHANGELOG.md`, `UPGRADING.md`; versioning semver e digest pinnati.
- **Test:** dry-run di release su tag `v4.1.0-rc1`; smoke test che parte dagli artefatti scaricati, non dal repo.
- **Release:** Gate 0 / 4.1.0

### 4.3 Kraken — sicurezza

#### KRAKEN-SEC-000 — Il servizio non si avvia (blocker assoluto)
- **Severità:** Critical (funzionale) · **Confidence:** Alta · **File:** `app/models/models.py:38-54`, `app/db/session.py:14`
- **Evidenza:** su `origin/main` `d86c8d5`, `commands: Any = relationship(...)` (idem `credentials`, `malware_samples`) su `class Base(DeclarativeBase)` fa sollevare a SQLAlchemy 2.0.30 `ArgumentError: Type annotation for "AttackEvent.commands" can't be correctly interpreted for Annotated Declarative Table form`. **Su `7fd50a9` il fix è già presente** (`__allow_unmapped__ = True` in ogni modello): import, Alembic e 58 test passano; restano 7 test che scrivono in `/app`.
- **Impatto:** nulla del progetto è utilizzabile; `docker compose up` va in crash loop; i "65+ test" non sono eseguibili.
- **Fix (già applicato in `7fd50a9`):** `__allow_unmapped__ = True` sui modelli (o annotazioni `Mapped[...]`). Non riapplicare: verificare che il commit sia pushato e importato.
- **Test:** `import app.main`, `alembic upgrade head`, `pytest tests/unit` verdi; immagine che parte.
- **Release:** 4.1.0 (verifica e push; non è più lavoro di codice)

#### KRAKEN-SEC-001 — Registrazione pubblica con ruolo admin dal client
- **Severità:** Critical · **Confidence:** Alta · **File:** `app/api/v1/endpoints/auth.py:82-95`, `app/schemas/schemas.py:26-29`
- **Evidenza (provata dal vivo):** `POST /api/v1/auth/register {"username":"pwner","password":"...","is_admin":true}` → `{"id":1,"is_admin":true}`; login → `/containers/active` 200, `/export/csv` 200.
- **Impatto:** chiunque diventa admin: export di tutti gli attacchi, comandi arbitrari nei sandbox (`/containers/exec`), distruzione sandbox, e con il socket montato la catena verso l'host.
- **Fix:** rimuovere `is_admin` da `UserCreate`; `is_admin=False` sempre; register disabilitato (`ALLOW_REGISTRATION=false`); primo admin solo via `scripts/create_admin.py`; audit dell'evento.
- **Test:** register con `is_admin:true` → 422 o utente non admin; register con flag off → 403.
- **Release:** 4.1.0 (bloccante)

#### KRAKEN-SEC-002 — Docker socket nel processo applicativo
- **Severità:** Critical · **Confidence:** Alta · **File:** `docker-compose.yml:65`
- **Evidenza:** `- /var/run/docker.sock:/var/run/docker.sock:ro`. `:ro` limita il filesystem del socket, non le API: chi lo apre crea container privilegiati, monta `/` dell'host ed esegue come root.
- **Impatto:** compromissione dell'host: tutti gli attacchi raccolti, `.env`, rete interna.
- **Fix:** rimuovere il socket dall'app; introdurre un `sandbox-broker` (socket-proxy con allowlist di soli `POST /containers/create`, `POST /containers/{id}/exec`, `DELETE /containers/{id}`, `GET /containers/json`) su rete dedicata, oppure runtime senza socket (rootless podman API, gVisor).
- **Test:** `/var/run/docker.sock` non esiste nel container app; create/exec/destroy funzionano via broker; tentativo di `POST /containers/create` con `Privileged:true` → 403 dal proxy.
- **Release:** 4.1.0 (bloccante)

#### KRAKEN-SEC-003 — Sandbox con uscita Internet
- **Severità:** Critical · **Confidence:** Alta · **File:** `app/services/docker_manager.py:120`, `app/core/config.py:31`, `docker-compose.yml:246`, `scripts/secure_sandbox.sh`
- **Evidenza:** `network=settings.SANDBOX_NETWORK` = `kraken_sandbox_net`, bridge con subnet e **senza** `internal: true`; `secure_sandbox.sh` blocca solo la LAN e **permette** 80/443 e DNS. Il servizio compose `kraken_sandbox` con `network_mode: none` non è quello usato dall'app. La docstring dichiara "no network access".
- **Impatto:** l'attaccante nell'honeypot usa la sandbox come pivot: C2, scansione, download payload, esfiltrazione. La promessa di isolamento è falsa proprio nella configurazione consigliata.
- **Fix:** rete `internal: true` senza gateway, DNS disabilitato, `network_mode: none` sul container creato; se serve detonazione con rete, rete separata con proxy egress allowlist e registrazione del traffico.
- **Test:** dalla sandbox `curl https://example.com` e `getent hosts example.com` falliscono; test in CI con `docker network inspect` che verifica `Internal: true`.
- **Release:** 4.1.0 (bloccante)

#### KRAKEN-SEC-004 — Estrazione sample senza limiti
- **Severità:** High · **Confidence:** Alta · **File:** `app/services/docker_manager.py:17-35`
- **Evidenza:** `content = f.read()` per ogni membro; path traversal corretto (verificato con tar malevolo: `../etc/passwd`, `/abs/evil`, `sub/../../escape` scartati), dimensione no.
- **Impatto:** un file grande scritto nella sandbox esaurisce la RAM dell'app durante la distruzione.
- **Fix:** cap per file (es. 64 MB) e per sessione (256 MB), streaming su disco con hash incrementale, contatore `malware_oversize`.
- **Test:** file 512 MB → scartato, evento registrato, RSS stabile.
- **Release:** 4.1.0

#### KRAKEN-SEC-005 — Password degli attaccanti in chiaro
- **Severità:** High · **Confidence:** Alta · **File:** `app/models/models.py:70`, `app/services/attack_service.py:34-38`, `app/services/siem.py`, `app/services/telegram.py`
- **Evidenza:** `password = Column(String(256))` in `CredentialAttempt`, valorizzata con `payload.password` in `attack_service.ingest_sensor_event`; nessuna redaction. Gli export CSV/JSON/PDF la restituiscono. **Non** è inviata a Telegram (il messaggio usa solo sensor/IP/paese/utente/sessione) e **non** è nel JSONL SIEM (che non include username/password).
- **Impatto:** GDPR e sicurezza: gli honeypot ricevono credenziali reali digitate per errore; un dump del DB o un export le espone. La superficie è DB + export, non i canali di notifica.
- **Fix:** salvare solo hash SHA-256 + pattern (lunghezza, classi, top-1000), redaction negli export e nei report, retention 30 giorni, esclusione dal backup; migrazione che azzera i valori esistenti.
- **Test:** ingest con password nota → nessun campo in chiaro su DB, export CSV/JSON/PDF, log; il valore originale non è recuperabile.
- **Release:** 4.1.0 (bloccante)

#### KRAKEN-SEC-006 — Segreti di default non validati
- **Severità:** High · **Confidence:** Alta · **File:** `docker-compose.yml:78,108,137`, `app/core/config.py:validate_secrets`
- **Evidenza:** `POSTGRES_PASSWORD:-kraken_pass`, `REDIS_PASSWORD:-kraken_redis_pass`, `GRAFANA_PASSWORD:-admin`; la validazione copre solo `SECRET_KEY` e `INTERNAL_API_KEY`.
- **Impatto:** accesso a dati degli attacchi e alle dashboard; Grafana admin espone datasource e credenziali.
- **Fix:** `:?` su tutti i segreti (compose non parte senza), validazione in `Settings` per DB/Redis/Grafana, nessuna porta pubblicata per db/redis/grafana.
- **Test:** compose senza `.env` → exit non-zero con messaggio; con password debole → rifiuto all'avvio.
- **Release:** 4.1.0 (bloccante)

#### KRAKEN-SEC-007 — API key interna non constant-time
- **Severità:** Low · **Confidence:** Alta · **File:** `app/core/security.py:86`, `app/api/v1/endpoints/containers.py:22`
- **Evidenza:** `api_key != settings.INTERNAL_API_KEY` e `==`.
- **Impatto:** timing attack sulla chiave che sblocca i sandbox.
- **Fix:** `hmac.compare_digest`.
- **Test:** unit sul comparatore.
- **Release:** 4.1.0

#### KRAKEN-SEC-008 — Nessuna CI sul repo GitHub
- **Severità:** Medium · **Confidence:** Alta · **File:** `.gitlab-ci.yml` (unico), `d86c8d5`
- **Evidenza:** nessuna `.github/workflows`; README dichiara 65+ test.
- **Impatto:** nessun gate su lint/test/bandit/pip-audit/build per il codice che va nel monorepo.
- **Fix:** portare i job in `.github/workflows/ci.yml` (ruff, pytest, bandit, pip-audit, `docker build`, trivy), con service container PG+Redis.
- **Test:** PR con test rotto → rossa; PR con CVE → rossa.
- **Release:** 4.1.0 (prima del merge)

#### KRAKEN-SEC-009 — Refresh token non revocabile
- **Severità:** Medium · **Confidence:** Alta · **File:** `app/api/v1/endpoints/auth.py` (login/refresh/logout), `app/db/redis.py`
- **Evidenza:** blacklist per jti solo dell'access; refresh è un JWT autonomo di 7 giorni, nessuna rotazione, nessun legame col dispositivo.
- **Impatto:** un refresh rubato sopravvive a logout e revoca; non esiste "termina tutte le sessioni".
- **Fix:** jti del refresh su Redis con single-use e rotazione, revoca globale per utente, riuso rilevato → invalidazione famiglia.
- **Test:** logout → refresh 401; riuso di un refresh consumato → 401 e revoca famiglia.
- **Release:** 4.1.0 (se esposto a Internet) altrimenti 4.2.0

#### KRAKEN-SEC-010 — TLS self-signed generato a runtime
- **Severità:** Medium · **Confidence:** Alta · **File:** `nginx/entrypoint.sh:1-12`, `nginx/nginx.conf`
- **Evidenza:** se mancano i certificati, il container genera `CN=localhost` e serve 443: il deploy "sembra" in TLS.
- **Impatto:** falsa percezione di sicurezza; client e browser falliscono la verifica, o l'operatore la disabilita.
- **Fix:** niente generazione automatica in produzione: fallire con messaggio esplicito; self-signed solo con `PROFILE=lab` dichiarato; HSTS solo con cert valido.
- **Test:** avvio prod senza cert → exit non-zero.
- **Release:** 4.1.0 (con KRAKEN-SEC-006)

#### KRAKEN-SEC-011 — Backup che chiama `docker exec`, non cifrato
- **Severità:** High · **Confidence:** Alta · **File:** `scripts/backup.sh`, `Dockerfile.backup`, `docker-compose.yml:kraken_backup`
- **Evidenza:** `docker exec kraken_db pg_dump ...` dentro il container di backup (nessun socket montato → il job fallisce), `redis-cli -a <password>` in argv, `tar ... || true` che nasconde gli errori, nessuna cifratura del dump, dei sample e della config.
- **Impatto:** backup inesistente o non verificato + copia in chiaro di malware e credenziali su un volume.
- **Fix:** `pg_dump` diretto via rete con `PGPASSWORD` da file, cifratura GPG AES-256 (`BACKUP_PASSPHRASE` obbligatoria), checksum, test di restore, sample esclusi o cifrati, retention con verifica.
- **Test:** backup eseguito in CI su compose; restore su DB vuoto; checksum confrontato; nessun file `.sql` in chiaro.
- **Release:** 4.1.0

### 4.4 Kraken — logica e affidabilità

| ID | Titolo | Sev | File | Impatto | Fix | Release |
|---|---|---|---|---|---|---|
| KRAKEN-LOGIC-001 | Ingest non idempotente (`session_id` UNIQUE, nessun upsert) | High | `models.py:33`, `attack_service.ingest_sensor_event` | il retry del sensore dopo timeout → IntegrityError → 500, evento perso | `INSERT ... ON CONFLICT (session_id) DO UPDATE` o upsert applicativo; risposta 200 con `duplicate: true` | 4.1.0 |
| KRAKEN-LOGIC-002 | Limite sandbox concorrenti fuori dal lock | Low | `docker_manager.py:58` | si superano i 20 dichiarati | check+insert sotto `async with self._lock` | 4.1.0 |
| KRAKEN-LOGIC-003 | Blacklist usata con `token[:32]` invece del jti | Low | `containers.py:35` | revoca non applicata su quegli endpoint | estrarre jti come in `deps.py` | 4.1.0 |
| KRAKEN-LOGIC-004 | `SANDBOX_API_URL` inutilizzato, URL hardcoded nei sensori | Low | `config.py`, `honeypot/sensors/*` | riconfigurazione impossibile | usare `settings.SANDBOX_API_URL` | 4.2.0 |
| KRAKEN-LOGIC-005 | Test unit scrivono in `/app` | Low | `tests/conftest.py:30` | 7 test falliscono fuori dal container | `tmp_path` + env `DATA_DIR` | 4.1.0 |
| KRAKEN-LOGIC-006 | Nessun limite a `commands[]` per sessione | Medium | `schemas.py:SensorEventIn` | un sensore ostile gonfia il DB | `max_length=200` + troncamento dichiarato | 4.1.0 |
| KRAKEN-OPS-001 | Prometheus: label `sha256_prefix` su counter | Medium | `app/core/metrics.py` | cardinalità illimitata → TSDB esploso | rimuovere la label, usare un counter senza label + esempio nel log | 4.1.0 |
| KRAKEN-OPS-002 | `attacks_total{country}` senza cap | Low | `app/core/metrics.py` | fino a ~250 serie (ok) ma cresce con GeoIP errato | normalizzare a ISO-3166 e `unknown` | 4.2.0 |
| KRAKEN-OPS-003 | Nessuna retention sui sample | High (legale) | `docker_manager._destroy` | crescita illimitata di malware su disco, senza scadenza | retention 30 giorni, quota volume, cancellazione sicura con audit | 4.1.0 |
| KRAKEN-OPS-004 | `eventi`/`comandi` senza paginazione dichiarata oltre 200 | Low | `endpoints/events.py` | export limitato a 10000 in memoria | cursore + streaming CSV | 4.2.0 |
| KRAKEN-SEC-012 | Sandbox con root filesystem scrivibile | High | `docker_manager.py:120` (`read_only=False`) | l'attaccante scrive binari persistenti nel container e li esegue | `read_only=True` + `tmpfs /tmp` 64 MB + `no-new-privileges` | 4.1.0 |
| KRAKEN-SEC-013 | `python-jose` 3.3.0 e 30+ advisory | High (SCA) | `requirements.txt` | CVE note su jose/ecdsa; gate SCA rosso | migrare a PyJWT (come Aegis) e rimuovere `python-jose`; bump dipendenze | 4.1.0 |
| KRAKEN-LOGIC-007 | Import JWT sbagliato e `jti` fallback `token[:32]` | Medium | `endpoints/containers.py` | revoca non applicata; confusione tra librerie | usare lo stesso decoder di `deps.py`, mai il fallback | 4.1.0 |
| KRAKEN-REL-001 | Commit `7fd50a9` non pushato | High (release) | repo Kraken | il fix di avvio esiste solo in locale; chi clona da GitHub non parte | push su `origin/main`, poi subtree; tag `v0.1.0` | Gate A |

---
## 5. Architettura di unione: due servizi, un piano di controllo

### 5.1 Perché due servizi e non un merge

| Criterio | Fondere Kraken nel Brain | Servizio separato |
|---|---|---|
| Blast radius | l'exploit dell'honeypot arriva al processo che firma gli update degli agenti | l'exploit resta in un container senza PKI né chiavi agenti |
| Privilegi | il Brain dovrebbe avere il Docker socket (peggior privilegio possibile) | solo Kraken ha il broker sandbox |
| Rischio malware | sample nello stesso filesystem del DB di audit | volume separato, retention separata |
| Scala | Brain pinned a 1 worker (stato in process) | Kraken scala orizzontalmente per numero di sensori |
| Rilascio | ogni fix honeypot richiede un redeploy del core SOC | ciclo indipendente |
| Compliance | dati di attaccanti insieme ai dati dei dipendenti | perimetri e retention distinti |

**Decisione (vincolante):** Kraken resta un **microservizio separato** con proprio processo, DB, migrazioni, ciclo di rilascio, rete, credenziali e **UI dedicata**. Aegis è il **piano di controllo** (identità, eventi, detection, incidenti, risposta); Kraken è un **servizio di deception e lab** che produce eventi e risultati di verifica. **È vietato fonderlo nel Brain** (logica, tabelle, privilegi, socket, esecuzione). L’unico accoppiamento ammesso è il contratto documentato (§5.3, §5.7).

### 5.2 Topologia target

```
                        ┌──────────────────────── Caddy (TLS, CSP, HSTS) ───────────────────────┐
                        │                                                                       │
   browser SOC ─────────┤ /                  → aegis-frontend   (SPA, vista unificata)          │
                        │ /api/*             → aegis-brain      :8000                            │
                        │ /ws/*              → aegis-brain      (WebSocket)                      │
                        │ /kraken/*          → kraken-ui/api    :9000  (UI dedicata + API)      │
                        │ /deception/*       → alias/compat verso /kraken/*                     │
                        └───────────────────────────────────────────────────────────────────────┘
                                   │                                     │
                          ┌────────▼─────────┐                 ┌─────────▼──────────┐
                          │   aegis-brain    │◄── ingest ──────│   kraken (app)     │
                          │  (controllo)     │  HMAC + key     │  deception + lab   │
                          └───┬──────┬───────┘  eventi/risultati└───┬────────┬──────┘
                              │      │                             │        │
                       ┌──────▼──┐ ┌─▼──────────┐          ┌───────▼──┐ ┌───▼────────┐
                       │ Postgres│ │ Redis      │          │ Postgres │ │ Redis      │
                       │ aegis   │ │ aegis:*    │          │ kraken   │ │ kraken:*   │
                       └─────────┘ └────────────┘          └──────────┘ └────────────┘
                              ▲                              ▲     ▲        ▲
                       agenti Guard/NodeTrace     sensori reali  topologie   run/scenari
                                                     broker sandbox ↔ container/reti lab (isolate)
```

Regole di confine (non negoziabili):

1. **Separazione totale**: Kraken non legge mai tabelle Aegis e viceversa; nessun import condiviso. Il Brain **non** contiene logica/runner/UI/lab di Kraken e **non** ottiene socket o privilegi di sandbox.
2. **Unica conversazione inter-servizio**: HTTP autenticato verso endpoint Aegis di ingest/risultati (`/api/v1/ingest/kraken` e feed in §5.7) con payload a contratto. Niente code/DB condivisi.
3. **Kraken non firma update, non conosce la PKI, non emette token Aegis.** Può accettare identità delegata per la UI (§5.5) ma resta autonomo.
4. **Il Brain non ha socket Docker** né credenziali dei sensori/lab. Solo il broker sandbox di Kraken media il runtime, con allowlist.
5. **Reti**: `edge`, `kraken_internal`, `sandbox` interna. Il **Kraken Lab** crea reti/container **per scenario**, isolate tra loro e, per default, senza egress verso host/LAN/Internet: l’osservazione verso Aegis avviene tramite eventi/risultati emessi dal servizio Kraken (§5.7), mai con collegamento di rete diretto del lab al Brain/DB di Aegis.
6. **UI distinte**: Kraken espone **UI dedicata** sotto `/kraken/*` per dati/operazioni proprie (sensori, sessioni, comandi, sample, campagne, topologie/run lab, configurazione). La SPA Aegis mostra solo la vista unificata/correlata (eventi, alert, incidenti, timeline, esito detection/risposta).

### 5.3 Contratto eventi (riuso di ciò che esiste)

Il Brain ha già il contratto giusto: `app/ingest/base.py` definisce `UnifiedEvent`, `make_event_id`, e `EventSource` enum. Kraken deve parlare **quello**, non inventarne un altro.

```jsonc
POST /api/v1/ingest/kraken
X-Api-Key: <chiave dedicata, scope "kraken:write", source "kraken">
Content-Type: application/json

{
  "events": [{
    "event_id": "kraken:5f2c...:1731530000:ssh",   // stabile, calcolato dal sensore
    "occurred_at": "2026-11-12T10:00:00Z",
    "host": { "hostname": "kraken-node-01", "os": "linux" },
    "source": "kraken",
    "category": "intrusion_attempt",
    "action": "login_attempt",
    "outcome": "failure",
    "severity": "medium",
    "user": { "name": "root" },                     // solo nome, mai password
    "network": { "src_ip": "45.9.20.7", "src_port": 51244,
                 "dst_ip": "203.0.113.10", "dst_port": 22, "protocol": "ssh" },
    "process": { "command_line": "uname -a" },      // comandi registrati dall'honeypot
    "raw": { "sensor": "ssh", "session_id": "5f2c...", "threat_level": "high",
             "geo": { "country": "RU", "asn": 49505 },
             "iocs": ["45.9.20.7", "d41d8cd9..."],
             "sample_sha256": "…", "mitre": ["T1110.001","T1059.004"],
             "context": "sensor", "run_id": null, "scenario_id": null, "topology_id": null },
    "tags": ["deception", "kraken"]
  }]
}
```

Vincoli da rispettare nel codice:

- **Idempotenza**: `event_id` deterministica (`sha256(sensor|session_id|timestamp|command_index)`); il Brain già deduplica per `event_id` (LRU Redis + fallback memoria). Il retry di Kraken diventa sicuro.
- **Batch**: massimo 500 eventi o 1 MB per richiesta. L'outbox è **una tabella Postgres in Kraken** (`outbox`), scritta nella stessa transazione dell'ingest: invio con backoff esponenziale + jitter, su 5xx ritenta, su 4xx scarta e logga (veleno). Redis non è l'outbox: è solo coda transiente.
- **Ordine**: nessuna garanzia globale; il Brain ordina per `occurred_at` e usa `SeqTracker` solo per gli agenti. Per Kraken, `occurred_at` è sufficiente (le sessioni durano minuti).
- **Auth**: HMAC-SHA256 del body con `KRAKEN_INGEST_SECRET` **più** `X-Api-Key` (scope `kraken:write`, vedi AEGIS-SEC-006). Così un replay senza firma non passa e una chiave rubata da sola non basta.
- **Timestamp**: se `occurred_at` è più vecchio di 24 h il Brain lo accetta ma marca `late=true`; oltre 7 giorni rifiuta (protezione da backfill malevolo).

**Mappatura sui campi esistenti** (non aggiungere campi al contratto se non serve):

| Concetto Kraken | `UnifiedEvent` | Tabella |
|---|---|---|
| sessione | `event_id` + `raw.session_id` | `siem_events` |
| comando eseguito | `process.command_line` | `siem_events` |
| credenziale tentata | `user.name` (solo nome) | `siem_events` |
| IP attaccante | `network.src_ip` | `siem_events` (indice) |
| livello di minaccia | `severity` | `siem_events` |
| sample | `raw.sample_sha256` | `malware_samples` (nuova, §9.3) |

### 5.4 Perché non Kafka, non Kubernetes, non object storage (oggi)

Tre motivi concreti, non ideologici:

1. **Volume reale**: un honeypot con 4 sensori produce 10³–10⁵ eventi/giorno. Redis list + HTTP batch regge, Kafka no (tre broker per essere serio, e va orchestrato).
2. **Competenza richiesta**: il progetto è gestito da una persona; ogni pezzo in più è un pezzo che si rompe di notte.
3. **Requisito di prodotto**: Aegis vende semplicità di deploy (`docker compose up`). Aggiungere un cluster contraddice il posizionamento.

Soglie per cambiare idea, da scrivere nel README: >5.000 eventi/s sostenuti, >30 giorni di buffer, più di 3 consumer indipendenti, o necessità di replay/riprocessing. A quel punto si valuta Redpanda, non Kafka.

**Kubernetes:** stesso ragionamento, con una soglia diversa. Oggi il prodotto vende `docker compose up` su un singolo nodo; un cluster K8s aggiungerebbe Ingress, cert-manager, storage class, NetworkPolicy, RBAC e un operatore da mantenere. Va introdotto solo in **5.1**, opzionale, con Helm chart e manifest provati su un cluster reale (non kind in CI), quando esiste un cliente che lo richiede o un requisito di HA multi-nodo. Mai nella 4.x. Se si arriva a K8s, i vincoli sono: NetworkPolicy default-deny, PodSecurity `restricted`, niente socket Docker, `readOnlyRootFilesystem`, e Kraken con broker sandbox su rete separata.

### 5.5 UI e autenticazione (dedicata + delegata)

**Principio:** Kraken è un servizio separato con **UI dedicata**; Aegis non la ingloba.

| UI | Dove | Responsabilità | Dati |
|---|---|---|---|
| **Kraken UI (dedicata)** | `/kraken/*` servita da Kraken | operazioni e analisi specifiche di Kraken | sensori/nodi, sessioni e comandi, sample/malware, campagne/fingerprint, **topologie e run del Lab**, configurazione, export Kraken |
| **Aegis SPA (unificata)** | `/` servita dal frontend Aegis | vista SOC unificata/correlata | eventi `source=kraken` normalizzati, alert, incidenti, timeline, esito detection/risposta/playbook |

Accesso:
- **SSO delegato (raccomandato nel deploy unito):** il Brain emette un token breve firmato (es. `POST /api/v1/deception/token`, `admin`/`analyst`, `exp` 5 min, `aud=kraken`); Kraken lo verifica con chiave pubblica del Brain (`KRAKEN_AEGIS_PUBKEY`) e mappa ruoli.
- **Login locale Kraken:** consentito solo per installazione standalone/lab isolato (`ALLOW_LOCAL_LOGIN=true`, profilo `lab`); in produzione unita preferibilmente disabilitato. KRAKEN-SEC-001/009 vanno corretti comunque (servizio distribuibile da solo).
- **Confini:** il token delegato dà accesso alla UI/API Kraken, non a privilegi Brain/PKI/agenti. La SPA Aegis mostra dati derivati dal contratto (§5.3, §5.7) e non duplica la gestione operativa Kraken-specifica.

### 5.6 Percorso di migrazione (senza big bang)

| Fase | Cosa | Rischio | Rollback |
|---|---|---|---|
| 0 | Kraken nel monorepo come `services/kraken`, CI verde, **nessun** contatto col Brain | nullo | rimozione directory |
| 1 | `POST /api/v1/ingest/kraken` + chiave scope + outbox in Kraken, feature flag `KRAKEN_INGEST_ENABLED=false` | basso | flag off |
| 2 | Kraken invia eventi **in shadow**: il Brain li salva e li marca `deception/lab`, nessuna detection | basso | flag off |
| 3 | UI dedicata Kraken (`/kraken/*`) per dati/ops proprie + vista unificata minima in Aegis SPA (eventi/incidente collegato) in sola lettura; regole Sigma su `source=kraken` abilitate solo a segnale stabile | medio | disattivare regole/vista |
| 4 | Kraken Lab in shadow: scenari/topologie eseguiti, risultati/evidenze in UI Kraken, correlazione con alert Aegis via contratto (nessuna azione automatica) | medio | disattivare run/scenari |
| 5 | Playbook/risposta su deception **opt-in** (dopo validazione Lab) e SSO delegato per accesso unificato | medio | disattivare playbook/SSO |

Ogni fase ha un criterio di uscita misurabile in §10.

### 5.7 Kraken Lab: architettura, isolamento e contratto di verifica

**Obiettivo:** rendere Kraken un ambiente di test/deception controllato che simula sottoreti e scenari per misurare se e come Aegis rileva/correla/risponde, senza mai diventare parte del Brain.

**Modello logico (tutto dentro il microservizio Kraken, mai nel Brain):**
- **Topologia**: definizione dichiarativa (YAML/JSON versionato) di reti, sottoreti/CIDR, host/ruoli, servizi/sensori esposti, profili e parametri.
- **Scenario**: sequenza riproducibile di azioni/TTP (bruteforce, movimento laterale simulato, beacon finto, drop sample, trigger canary) con seed, durata, intensità e precondizioni; referenzia una topologia.
- **Run**: istanza di esecuzione (scenario × topologia × ambiente) con stato (`planned/running/passed/failed/aborted`), finestra temporale, log/artefatti, hash della definizione e owner.
- **Expectation/asserzione**: esito atteso da Aegis (alert su regola X, severità ≥ Y, correlazione/incidente, comando/ack entro T). Le asserzioni sono valutate da Kraken confrontando i risultati osservati.
- **Evidenza**: pacchetto esportabile (definizioni, eventi emessi, comandi, timestamp, alert/incidenti correlati, esito per asserzione).

**Isolamento e sicurezza (vincoli):**
- Reti lab **per scenario**, `internal`/senza egress di default; nessun route verso `edge`, host, LAN o Internet salvo proxy egress esplicitamente abilitato, allowlistato e auditato.
- Esecuzione solo tramite **sandbox-broker** con allowlist; immagini controllate, limiti CPU/RAM/PID, `no-new-privileges`. Mai montare socket/privilegi nel Brain; mai dare al Brain accesso al lab.
- Separazione “lab” vs “sensori reali”: run marcati (`source=kraken`, `context=lab`, `run_id`, `scenario_id`, `topology_id`); risposta automatica disabilitata sui run `lab` salvo opt-in esplicito.
- Un fallimento/compromissione in un run non deve impattare altri run, il servizio Kraken core o Aegis.

**Collegamento ad Aegis (contratto, microservizio↔microservizio):**
- **Eventi**: Kraken emette `UnifiedEvent` verso `POST /api/v1/ingest/kraken` (§5.3) aggiungendo in `raw` `context:"lab"|"sensor"`, `run_id`, `scenario_id`, `topology_id`, `step`, `expected` (opzionale) e tag `["kraken","lab"]`/`["kraken","deception"]`. Idempotenza e HMAC+scope invariati.
- **Verifica detection**: Kraken consulta/esporta gli esiti (alert/incidente/comandi/ack) tramite API Aegis read-only con chiave scope dedicato (es. `kraken:read_results`) o feed normalizzato; correla per `event_id`/`run_id`/finestra e produce il verdetto (detected, correlated, responded, missed, false_positive) salvato ed esposto nella **UI Kraken**.
- **Modalità**: `shadow` (eventi marcati lab, nessuna azione automatica, misura detection) → `active` (solo dopo approvazione, scope esplicito, playbook opt-in). Il Brain applica le sue policy; Kraken registra l’esito.
- **Nessuna dipendenza inversa**: Aegis non chiama runtime interni del lab e non dipende dal DB Kraken; consuma solo contratti.

---

## 6. Piano dei fix, in ordine di esecuzione

Gli effort sono per una persona che conosce il codice; includono test e PR, non la review.

### 6.0 Cancello 0 — "il prodotto è distribuibile" (4–6 giornate)

Questo cancello non è codice: è ciò che separa un repository da un prodotto. Non blocca lo sviluppo della 4.1.0, ma blocca qualunque tag pubblico, pilot con clienti o annuncio.

| # | ID | Azione | Effort | Verifica |
|---|---|---|---|---|
| 1 | AEGIS-REL-001 | Licenza **AGPL-3.0-only** (D1): `LICENSE`, `NOTICE`, `TRADEMARK.md`, `THIRD_PARTY_NOTICES.md`, header SPDX nei file nuovi | 2–4 h | `LICENSE` presente; check CI; SPDX coerente |
| 2 | — | `SECURITY.md` con disclosure policy, scope, tempi di risposta; `CONTRIBUTING.md` con licenza, regole di commit e pull request | 4 h | file presenti; link dal README |
| 3 | AEGIS-REL-002 | Release pipeline completa: immagini Brain/Link/Frontend, NodeTrace, Guard, compose bundle, SBOM per componente, checksum, firma cosign, `CHANGELOG.md`, `UPGRADING.md` | 2–3 gg | release `rc` installabile dagli artefatti su una macchina pulita |
| 4 | — | Privacy/GDPR: registro trattamenti, DPA template, retention dichiarata, data residency; per Kraken, dati degli attaccanti separati | 1–2 gg (legale) | documenti firmabili; nessun dato personale nei log |
| 5 | — | Nome e marchio: ricerca «Aegis» (molti prodotti omonimi), verifica trademark, dominio, package name | 0,5 gg | parere; naming alternativo se necessario |

**Uscita:** un cliente può ricevere un pacchetto versionato, sa dove segnalare una vulnerabilità, e il codice ha una licenza valida. Senza questo, la 4.1.0 non si tagga.

> **Nota legale:** il titolare è minorenne. AGPL non richiede un contratto negoziato; evitare EULA, CLA e accordi commerciali senza tutore/legale. La policy sul marchio è interna e non sostituisce una registrazione.

### 6.1 Cancello A — "Kraken esiste" (3–4 ore)

Ordine obbligato, perché tutto il resto presuppone un servizio che parte.

| # | ID | Azione | Effort | Verifica |
|---|---|---|---|---|
| 1 | KRAKEN-REL-001 | **autorizzazione esplicita**, poi push di `7fd50a9` su `origin/main` e subtree in `services/kraken`; verifica SEC-000 | 30 min + attesa | `import app.main`; `alembic upgrade head`; `pytest` |
| 2 | KRAKEN-LOGIC-005 | test in `tmp_path`, `DATA_DIR` configurabile | 45 min | `pytest tests/unit` 65/65 |
| 3 | KRAKEN-SEC-008 | `.github/workflows/ci.yml` con PG+Redis | 90–120 min | PR rossa se test/audit falliscono |
| 4 | — | `ruff check`, `ruff format`, `mypy` (soft) | 30 min | job verde |

**Uscita:** `pytest` verde su GitHub, immagine che parte, `/health` 200.

> **Regola:** `git subtree add` crea un commit. Senza un «sì» esplicito al push e al subtree, Gate A resta fermo e si lavora su Gate 0. Non simulare il consenso.

### 6.2 Cancello B — "Kraken non è un rischio" (5–6 giornate; 41–45 h)

| # | ID | Azione | Effort | Note |
|---|---|---|---|---|
| 1 | KRAKEN-SEC-001 | `is_admin` fuori da `UserCreate`; register off; script primo admin; audit | 3 h | la più urgente: privesc banale |
| 2 | KRAKEN-SEC-002 | broker socket-proxy con allowlist; app senza socket | 1–1,5 gg | il lavoro più delicato del cancello |
| 3 | KRAKEN-SEC-003 | rete `internal: true`, `network_mode: none`, DNS off, test `docker network inspect` | 3 h | |
| 4 | KRAKEN-SEC-005 | hash+pattern password, redaction su log/SIEM/Telegram | 4 h | |
| 5 | KRAKEN-SEC-006 | `:?` su tutti i segreti, validazione, porte non pubblicate | 2 h | |
| 6 | KRAKEN-SEC-010 | niente TLS auto-generato fuori da `lab` | 1 h | |
| 7 | KRAKEN-SEC-007 | `hmac.compare_digest` | 15 min | |
| 8 | KRAKEN-SEC-004 | cap per file/sessione, streaming con hash | 3 h | |
| 9 | KRAKEN-SEC-011 | backup senza `docker exec`, GPG, checksum, restore testato | 6 h | |
| 10 | KRAKEN-SEC-009 | refresh single-use con rotazione e revoca famiglia | 5 h | |
| 11 | KRAKEN-LOGIC-001/002/003/006, KRAKEN-OPS-001 | upsert idempotente, lock, jti, limiti, rimozione label `sha256_prefix` | 6 h | |

**Uscita:** nessun Critical aperto; privesc e pivot riprodotti e non più possibili; backup restaurabile.

### 6.3 Cancello C — "Aegis torna verde" (7–7,5 giornate; 56–60 h)

| # | ID | Azione | Effort |
|---|---|---|---|
| 1 | AEGIS-LOGIC-006 | corpus sintetico relativo a `now` o `freezegun`; 2 test verdi a qualunque data | 3 h |
| 2 | AEGIS-LOGIC-007 | marker `integration` o fixture DB sui 5 test | 2 h |
| 3 | AEGIS-LOGIC-008/009 | rimozione `pymongo`/`motor`; PyJWT 2.15.0 | 1 h + verifica |
| 4 | AEGIS-OPS-005 | bump Vite; audit dev separato dal gate prod | 2 h |
| 5 | AEGIS-SEC-011 | rimozione ramo curl o `--config` 0600 in NodeTrace | 3 h |
| 6 | AEGIS-SEC-001 | re-enroll con prova di possesso (machine-id + token dedicato) | 1–1,5 gg |
| 7 | AEGIS-SEC-002 | separazione chiavi enroll/firma/device; Ed25519 nel one-liner, HMAC rimosso | 1 gg |
| 8 | AEGIS-SEC-007 | `reg delete /v`, esiti onesti, Linux `unsupported` | 4 h + test Windows |
| 9 | AEGIS-SEC-004 | decompressione incrementale con cap | 3 h |
| 10 | AEGIS-SEC-005/008 | profili `lab/pilot/prod`, Redis per rate limit, FFP on in prod | 4 h |
| 11 | AEGIS-LOGIC-003/004/005 | coda con priorità + contatori, revoca fail-closed, chiave health corretta | 2 h |
| 12 | AEGIS-SEC-003 | `script` → catalogo azioni (o container effimero) | 5 h |
| 13 | AEGIS-SEC-006 | tabella `api_keys` con scope e revoca | 1 gg |
| 14 | AEGIS-OPS-002 | job di restore verificato | 3 h |

**Uscita:** CI completamente verde, 0 High da `pip-audit`/`npm audit`, nessun finding Critical/High aperto in Aegis.

### 6.4 Cancello D — "integrazione" (9–10 giornate)

Solo dopo A+B+C. Voci: §5.3 (ingest), §5.5 (SSO), §5.6 fasi 1–3,
§10 (4.1.7–4.1.9): outbox, UI Kraken, vista Aegis, compose e smoke test.

**Totale fino a 4.1.0 production-ready: 27–28 giornate uomo di lavoro netto**
(Gate A 0,5 + B 5,5 + C 7,5 + D 9,5 + overhead di integrazione), di cui ~15 su
Kraken. Con il 20% di buffer si arriva a **33–34 giornate**, cioè **6,5–7
settimane a 40 h** o **8,5–9 settimane a 30 h**. Con D16 (30 h) la 4.1.0 è
~9 settimane di lavoro netto, senza una data di calendario. Il Gate 0 (4–6
giornate, in parte legali) è aggiuntivo. La stima v2.1 di 9–13 giornate era
otimistica di circa il 60%; la v2.6 di 17–18 giornate era corretta per il
vecchio perimetro senza UI, non per questo.

### 6.5 Come provare ogni fix (ricette)

```bash
# Kraken, prima e dopo KRAKEN-SEC-000
cd services/kraken && python -c "import app.main" && alembic upgrade head && pytest -q

# Privesc (deve fallire dopo il fix)
curl -s -X POST localhost:9000/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"x","password":"Str0ng!pass","email":"x@y.z","is_admin":true}' | jq

# Isolamento sandbox (deve fallire dentro il container)
docker run --rm --network kraken_sandbox_net alpine sh -c 'wget -T2 -qO- https://example.com; echo rc=$?'

# Socket (deve mancare)
docker compose exec kraken ls -l /var/run/docker.sock   # atteso: No such file

# Aegis CI
cd aegis-brain && REQUIRE_INTEGRATION=1 pytest -q && pip-audit -r requirements.txt
cd ../frontend && npm audit --audit-level=high --omit=dev && npm run build

# Firma OTA (dopo AEGIS-SEC-002)
curl -s -X POST localhost:8000/api/v1/deploy/artifacts/.../sign ... && \
  java -jar aegis-guard/... # verifica del manifest firmato
```

---
## 7. Feature nuove per Aegis (oltre i fix)

Ogni voce: problema che risolve, cosa costruire, dove, criterio di accettazione, effort. Sono ordinate per rapporto valore/costo, non per release: la distribuzione è in §10.

### 7.1 Contenimento di rete vero (host isolation)
- **Problema:** `isolate` oggi è un flag nel DB (`agent.isolated`) più un comando all'agente; se l'agente non risponde, l'host resta in rete. Non esiste isolamento lato infrastruttura.
- **Costruire:** connettore al firewall/switch (API pfSense/OPNsense, FortiGate, UniFi) e alle security group cloud (AWS SG, Azure NSG, GCP firewall) con azione `quarantine_host(ip, duration)`; TTL obbligatorio (default 60 min) e ripristino automatico; audit con motivazione; "kill switch" globale che rifiuta nuovi isolamenti se il controllo è degradato.
- **Accettazione:** incidente con IP → regola creata in <3 s sul firewall di test, host non raggiungibile da altro host, ripristino automatico a scadenza, audit completo; integrazione provata su un target simulato (nessun hardware in CI).
- **Effort:** 4–5 gg (uno per famiglia di connettore).
- **Perché conta:** è l'unica azione che funziona quando l'agente è compromesso o spento. Oggi il prodotto promette contenimento e consegna un flag.

### 7.2 Contenimento credenziali (disable/reset con approvazione)
- **Problema:** dopo un attacco a credenziali (T1110, T1078) il SOC isola la macchina ma non la credenziale: l'attaccante la riusa altrove.
- **Costruire:** azione `disable_account` verso AD (LDAP modify / `Disable-ADAccount` via WinRM), Okta, Google Workspace, M365; flusso a due persone (richiesta + approvazione) con scadenza; registro delle azioni con esito.
- **Accettazione:** alert brute-force → proposta di disabilitazione → approvazione → account disabilitato sull'AD di test → audit con due identità.
- **Effort:** 4 gg.
- **Nota:** richiede la rimozione di WinRM dal "rito" del deploy: qui serve, ma con allowlist di comandi e credenziali dedicate, non con l'account di dominio dell'operatore.

### 7.3 Timeline unificata investigativa (vista Aegis)
- **Problema:** la SPA ha pagine per alert, eventi SIEM, telemetria, incidenti, ma nessuna vista che li metta **in ordine** per un host o un IP.
- **Costruire:** `GET /api/v1/timeline?subject=ip:1.2.3.4&from=...&to=...` che unisce `siem_events`, `telemetry_events`, `alerts`, `agent_commands`, `deception_events` (inclusi eventi `context=lab` marcati) con `source`, `severity`, `link`; UI con virtualizzazione (10k righe), filtri (incluso `context` lab/sensor) e "pin"; export JSON. Dettagli operativi Kraken-specifici (topologia, step scenario, sessione raw) restano nella **UI dedicata Kraken** via deep-link.
- **Accettazione:** per un IP con eventi da 3 sorgenti, la vista mostra l'ordine corretto, p95 < 400 ms su 10k righe, link a ogni entità; eventi lab distinguibili e filtrabili.
- **Effort:** 3 gg (1 backend, 2 frontend).

### 7.4 ATT&CK coverage navigabile
- **Problema:** 14 tecniche MITRE sono un numero, non una vista. Il cliente non sa cosa è coperto e cosa no.
- **Costruire:** matrice ATT&CK Enterprise in UI con stato per tecnica (`covered` con N regole, `partial`, `none`), filtro per piattaforma, click → regole e ultimi alert; endpoint `GET /api/v1/detections/coverage?platform=windows`; export per il report al cliente.
- **Accettazione:** la matrice riflette `get_engine().coverage()` (stessa fonte, nessun dato duplicato); aggiungere una regola cambia la vista senza deploy.
- **Effort:** 2 gg.
- **Onestà:** mostrare i buchi è un rischio commerciale, ma è l'unica cosa che rende credibile il numero.

### 7.5 Detection-as-code con validazione in CI
- **Problema:** regole Sigma e di correlazione si aggiungono a mano; non c'è un test che dica "questa regola non compila" prima del merge.
- **Costruire:** `scripts/validate-rules.py` (compila ogni regola, verifica campi, MITRE, severità, `falsepositives`, presenza di almeno un evento positivo e uno negativo nel corpus), job CI, pre-commit hook; `make rules`.
- **Accettazione:** regola con campo inesistente → CI rossa con messaggio preciso; corpus replay resta F1 1.0.
- **Effort:** 1,5 gg.

### 7.6 Report PDF unificato (incidente + deception)
- **Problema:** Kraken ha un export PDF proprio, Aegis ha export CSV/JSON ma nessun report d'incidente impaginato. Il cliente chiede un PDF.
- **Costruire:** generatore server-side (WeasyPrint o ReportLab) con template: executive summary, timeline, host coinvolti, IOC, azioni intraprese, eventi deception, allegati; `GET /api/v1/incidents/{id}/report.pdf`; brandizzabile; watermark "CONFIDENTIAL".
- **Accettazione:** PDF generato in <5 s per un incidente con 500 eventi; nessun nome utente/password in chiaro; test di regressione sul testo estratto.
- **Effort:** 3 gg.

### 7.7 Threat intel: feed e arricchimento
- **Problema:** gli IP sono arricchiti con GeoIP, non con reputazione. Il SOC vede `45.9.20.7` e non sa che è un noto scanner.
- **Costruire:** import di feed (MISP, AlienVault OTX, abuse.ch, liste CIDR custom) in tabella `ioc(type, value, source, confidence, first_seen, last_seen, tags)`; arricchimento async con cache Redis 24 h; l'IP catturato da Kraken è automaticamente arricchito; matching nelle regole come campo `ioc.reputation`.
- **Accettazione:** IP presente in feed → `reputation: malicious` in <1 s dalla cache; feed irraggiungibile → degradazione senza errori; nessuna chiamata esterna per IP privati (RFC1918) — importante: oggi l'arricchimento non distingue.
- **Effort:** 4 gg.

### 7.8 Notifiche e turni (alert routing)
- **Problema:** un solo canale (Telegram nei playbook, email opzionale). Nessuna escalazione, nessuna finestra di reperibilità, nessun "chi è di turno".
- **Costruire:** canali multipli (Slack, Teams, webhook generico, PagerDuty-compatibile), routing per severità/tag/orario, dedup con finestra, acknowledge con tracking (`ack_by`, `ack_at`, MTTA), escalazione a T+15/T+30.
- **Accettazione:** alert high fuori orario → canale secondario; ack ferma l'escalazione; MTTA esposto in dashboard.
- **Effort:** 4 gg.
- **Perché:** è la feature che i SOC piccoli chiedono per prima dopo il deploy.

### 7.9 Soppressioni governate
- **Problema:** la tentazione dell'analista è disattivare la regola; poi nessuno la riattiva.
- **Costruire:** `suppressions(rule_id, scope, reason, created_by, expires_at)` con TTL obbligatorio (max 90 gg), contatore "alert soppressi", pagina di revisione settimanale, alert quando una soppressione scade.
- **Accettazione:** soppressione senza `expires_at` → 422; scaduta → alert torna; report mensile dei soppressi.
- **Effort:** 2 gg.

### 7.10 Affidabilità del Brain
- **Problema:** il Brain gira con un worker e stato in process (dedup, rate limit, cache). In HA l'overlay esiste ma non è provato; un riavvio perde lo stato.
- **Costruire:** stato condiviso su Redis con chiavi namespaced e TTL; `uvicorn --workers N` dietro Caddy; test di concorrenza su dedup; `/readyz` che fallisce se Redis non è raggiungibile e lo stato è richiesto.
- **Accettazione:** 2 worker, stesso `event_id` inviato in parallelo → 1 record; riavvio di un worker senza perdita di coda; test di carico 200 rps sostenuti con p95 < 300 ms.
- **Effort:** 4 gg.

### 7.11 Onboarding e proof-of-value in 15 minuti
- **Problema:** il primo deploy richiede secret, migrazioni, enroll, agenti, regole: un consulente impiega mezza giornata e il cliente non vede valore.
- **Costruire:** `make demo` che alza compose con dati sintetici (3 host, 20 alert, 2 incidenti, 1 attacco deception), una pagina "Guided tour" e `scripts/smoke-test.sh` che verifica 12 percorsi critici.
- **Accettazione:** da clone pulito a dashboard popolata in <15 min su un portatile; nessun secret reale; `smoke-test.sh` verde.
- **Effort:** 2 gg.

### 7.12 Cosa NON fare adesso (e perché)
| Idea | Motivo del rinvio |
|---|---|
| Multi-tenancy | cambia lo schema di ogni tabella e le policy di ogni endpoint: 6+ settimane, e nessun cliente lo ha chiesto |
| EDR completo (kernel driver Windows) | richiede firma del driver, WHQL, supporto: è un altro prodotto |
| Market di playbook | senza clienti non c'è domanda; prima servono 20 playbook interni solidi |
| Case management con SLA e bolle di fatturazione | utile, ma dopo la timeline unificata (7.3), che ne è il presupposto |
| AI generativa che "decide" il contenimento | rischio troppo alto; l'AI resta in supporto all'analista (riassunti, query) |
| Kubernetes nella 4.x | il prodotto vende un singolo compose; un cluster aggiunge superficie e costi di supporto senza clienti che lo chiedano (5.1 opzionale) |
| Kafka nella 4.x | a 10³–10⁵ eventi/giorno è infrastruttura senza beneficio; le soglie sono in §5.4, e prima di Kafka si valuta Redpanda/NATS |
| Multi-tenant vero | cambia schema, RBAC e backup; per il mid-market basta un deployment per cliente (5.0+ per MSSP) |

---

## 8. Espansione significativa di Kraken

Kraken oggi è un honeypot che raccoglie attacchi. Per avere valore nel prodotto deve diventare **una piattaforma di deception**: sensori, esche, detonazione, intelligence e reporting. Le voci sono ordinate per dipendenza.

### 8.1 Sensori aggiuntivi (impegno: 6–8 gg)
1. **SMB (porta 445)** — il più richiesto: cattura EternalBlue-like, PsExec, ransomware che cifra share esche. Implementazione: server SMB minimale (impacket o implementazione async) che accetta NTLM e registra hash NetNTLMv2 (utilissimi: cracking e relay detection), share `Documents`, `Backup`, file esca con canary. **Attenzione:** non implementare relay/SMB signing debole; solo cattura.
2. **RDP (3389)** — non si emula il protocollo: si registra il tentativo (TCP + negoziazione), si offre un banner credibile e si logga l'IP; opzionale integrazione con `xrdp` in container per sessioni finte.
3. **Modbus/ICS (502) e S7 (102)** — honeypot per reti OT: risponde a read/write di registri finti, registra le scritture (indicatore di attacco a processo fisico). Richiede cautela: nessuna risposta che possa simulare un impianto reale in produzione.
4. **LDAP (389)** — cattura bind e query di enumerazione.
5. **MySQL/Postgres finti (3306/5432)** — cattura credenziali e tentativi di `COPY ... FROM PROGRAM` (RCE storica).
6. **HTTP "vulnerabile"** — template per WordPress/phpMyAdmin/ Jenkins/Confluence con endpoint che fingono CVE note (path specifici: `/wp-content/plugins/...`, `/solr/admin/cores`, `/script` di Jenkins), registrando il payload.
7. **SMTP aperto (25)**, **DNS (53)** — misura di abuso (open relay, amplification) con registrazione delle query.

Regola comune: **un sensore = un modulo** con interfaccia `Sensor` (`name`, `listen`, `parse`, `emit`), configurazione da YAML, abilitabile per nodo, health check, metriche `kraken_sensor_up`.

### 8.2 Sensori come flotta (2–3 gg)
- Ogni nodo ha `node_id`, una **chiave per nodo** (non una condivisa), registrazione con token monouso, heartbeat, versione, configurazione applicata, stato sensori.
- `POST /api/v1/nodes/register` + `GET /api/v1/nodes/{id}/config` (firma Ed25519 come per gli agenti Aegis: riuso del pattern, non della chiave).
- Aggiornamento configurazione con conferma (desired/applied) e rollback automatico se il nodo non conferma in 10 min.
- **Accettazione:** un nodo compromesso non può impersonarne un altro né leggere la config degli altri; revoca immediata; nessun secret in chiaro nel DB (solo hash).
- **Perché:** senza flotta, "honeypot" significa un server. Con flotta significa 20 esche in 20 subnet, che è ciò che rende la deception efficace.

### 8.3 Detonazione e analisi sample (4–6 gg)
- **YARA** sui sample catturati (regole proprie + `yara-rules` community), con regola di quarantena e `malware_samples.detections`.
- **Hashing e identificazione**: SHA-256, ssdeep, `file(1)`/`python-magic`, strings estratte con IOC (IP, domini, URL, base64 lungo), ClamAV opzionale.
- **Sandbox di detonazione separata** (non la sandbox interattiva): container `internal`, timeout 120 s, `strace`/`sysdig` se disponibile, cattura di file creati e processi, nessuna rete. Output: `behavior` JSON, `iocs[]`, MITRE mappate.
- **Accettazione:** caricare un ELF di test → hash, tipo, IOC, YARA match, report; nessuna rete usata (verificato); timeout rispettato; sample non eseguibile dall'app.
- **Nota di sicurezza:** la detonazione è la parte più pericolosa del prodotto. Deve stare in un container senza socket, con utente non privilegiato, `seccomp` default, `no-new-privileges`, e non deve mai condividere il volume con l'app.

### 8.4 Threat intelligence e attribuzione (3 gg)
- Arricchimento IP/ASN/paese con cache; **cluster di campagne**: raggruppare sessioni per `src_ip` + fingerprint comandi (hash dei comandi normalizzati) + user-agent, con soglia temporale.
- **Fingerprint attaccante**: `HASSH` per SSH (client), `JA3/JA4` per TLS se il sensore lo consente, `p0f`-like per TCP; salvare e usare per collegare sessioni da IP diversi (botnet, proxy rotation).
- **Accettazione:** due sessioni dallo stesso client SSH con IP diversi → stesso `attacker_fingerprint`; la UI le mostra raggruppate.
- **Perché:** è la differenza tra "log di attacchi" e "intelligence".

### 8.5 Deception attiva: canary token e file esca (3 gg)
- Generatore di canary token (URL, DNS, documento Word/PDF con beacon, AWS key finta, cookie) con tracking del trigger → evento `canary_triggered` ad alta severità.
- Distribuzione di file esca nei share e nelle directory utente (via agente Aegis o manuale) con nome credibile e `canary_id` nel contenuto.
- **Accettazione:** aprire il PDF esca genera un evento con IP, user-agent, `canary_id`, host di provenienza; il file non contiene macro attive.
- **Perché:** è la feature che sposta Kraken da "attira attaccanti esterni" a "scopre attaccanti interni e ransomware", che è ciò che il cliente compra.

### 8.6 Risposta automatica su deception (2–3 gg)
- Su `deception_event` con `severity >= high`: arricchisci → crea incidente in Aegis → proponi playbook `block_ip` (firewall) e `disable_account` se la credenziale esca è stata usata → ticket.
- Regola d'oro: **le credenziali esca non devono esistere** in AD; se qualcuno le usa, è un attaccante (o un test). Questo va scritto nell'UI, perché un falso positivo qui è costoso.
- **Accettazione:** attacco a sensore SSH → incidente creato in <10 s, playbook proposto, IP bloccato al firewall di test, audit completo.

### 8.7 Blocklist e export operativo (2 gg)
- Export per famiglia: CIDR/IP, domini, hash, user-agent, JA3, con TTL e formato per firewall (iptables, pfSense, FortiGate, Cloudflare, `ipset`).
- API `GET /api/v1/intel/blocklist?since=...&format=...` con firma e versione, pensata per il consumo automatico.
- **Accettazione:** blocklist generata in <2 s con 10k IP, deduplicata e normalizzata, nessun IP privato incluso.

### 8.8 STIX/TAXII e MISP (3–4 gg)
- Export STIX 2.1 di indicatori e campagne; server TAXII minimale (collections read-only) o push verso MISP con `MISP_URL`/`MISP_KEY`.
- **Accettazione:** un bundle STIX validato con `stix2-validator`; import in MISP di test; nessuna dipendenza da servizi esterni in CI (mock).

### 8.9 Dollhouse e contenuti dinamici (4 gg)
- Generazione di filesystem e servizi finti per il container sandbox (utenti finti, `/etc/passwd` credibile, cron, `.ssh`, `.aws/credentials` esca, `/var/www` con sorgenti finti) così che l'attaccante scarichi altro materiale e riveli TTP.
- **Accettazione:** il container parte con il dollhouse in <2 s; nessun file reale; ogni file esca ha `canary_id` e, se letto, genera evento (watcher `inotify`).
- **Perché:** aumenta il tempo di dwell e la qualità dei comandi raccolti, che è il dato che si vende.

### 8.10 Metriche di prodotto (1–2 gg)
- Dashboard "Deception effectiveness": sessioni/giorno, IP unici, comandi per sessione, tempo medio di dwell, credenziali provate, sample catturati, top TTP, paesi, campagne.
- Report settimanale automatico (PDF) con la stessa pipeline del report d'incidente (§7.6).
- **Accettazione:** la dashboard si popola da dati reali del compose demo; i numeri tornano con query SQL dirette (test di coerenza).

### 8.11 Roadmap tecnica Kraken (riordino del codice)
Oggi: `app/api/v1/endpoints/*`, `services/*`, `models/models.py` monolitico, sensori in `honeypot/`. Proposta per il monorepo (microservizio separato, con UI e Lab propri):

```
services/kraken/
  app/
    api/v1/endpoints/{auth,nodes,sensors,events,malware,intel,lab,results,metrics,health}.py
    core/{config,security,logging,metrics}.py
    db/{session,redis}.py
    models/{base,attack,node,malware,ioc,canary,lab,run}.py
    services/{attack,sandbox_broker,siem,telegram,enrich,outbox,lab_runner,verifier}.py
    sensors/{base,ssh,http,ftp,telnet,smb,rdp,ldap,sql}.py
    lab/{topologies,scenarios,assertions,profiles}/
    schemas/{auth,event,node,malware,intel,lab,run}.py
  ui/                                                     # UI dedicata Kraken
  alembic/versions/
  tests/{unit,integration,lab,fixtures}/
  deploy/{docker-compose.yml,Dockerfile,sandbox-proxy/}
```

Nessuna riscrittura: si sposta e si divide mentre si toccano i file per i fix. Il "big bang refactor" è vietato.

### 8.12 Kraken Lab — sottoreti simulabili, scenari e verifica detection Aegis

**Scopo:** trasformare Kraken in un lab configurabile e riproducibile per simulare sottoreti/ambienti e verificare se Aegis rileva, correla e risponde (ambiente di test collegato ad Aegis), mantenendo Kraken come **microservizio separato** con UI dedicata.

**Capacità da costruire (incrementale):**
1. **Topologie configurabili (sottoreti):** definire reti e sottoreti (CIDR, segmenti es. `dmz`, `corp`, `ot`, `guest`), host/nodi virtuali, servizi/sensori per host, isolamento tra segmenti e profili riusabili; versionate e validate (no overlap invalido, limiti risorse).
2. **Scenari riproducibili:** catalogo di scenari/TTP (bruteforce, spray, enum, movimento laterale simulato, beacon finto, drop/esecuzione sample controllata, trigger canary) con parametri, seed e mapping a regole/tecniche MITRE attese; composizione scenario+topologia.
3. **Runner e orchestrazione:** avvio/stop run, pianificazione, concorrenza limitata, stato live, log/artefatti, timeout e cleanup garantito; esecuzione solo via broker e reti per-scenario (§5.7).
4. **Verifica end-to-end con Aegis:** emissione eventi `context=lab` verso ingest Aegis e raccolta esiti (alert, correlazione/incidente, comando/ack, tempi) tramite contratto read-only/feed; valutazione asserzioni e verdetto (detected/correlated/responded/missed/false_positive) con tempi (MTTD/MTTR di test).
5. **Evidenze e report:** in UI Kraken, dettaglio run (topologia, step, eventi, esiti Aegis correlati, verdetti) ed export evidenze; sintesi in Aegis solo come stato/esito correlato (link alla UI Kraken).
6. **Modalità e safety:** `shadow` di default (misura detection, nessuna risposta automatica reale); `active` solo opt-in con scope approvato. Run sempre etichettati per escluderli dalle metriche operative reali.
7. **Libreria e regressione:** scenari "golden" legati alla copertura detection (§7.4/7.5) per evitare regressioni (ripetibili su CI con Docker, marcati lab).

**Accettazione (complessiva, per fasi):**
- Una topologia con ≥2 sottoreti e ≥3 host viene creata, validata ed eseguita in reti isolate; teardown completo.
- Uno scenario mappato a una regola nota produce evento lab → alert/risultato Aegis correlato → verdetto ed evidenza in UI Kraken.
- Nessuna logica di lab eseguita nel Brain; Brain/DB Aegis non raggiungibili dal piano dati del lab se non tramite ingest/contratto.
- UI Kraken mostra topologie, run, risultati e sample/sessioni; SPA Aegis mostra solo esito/correlazione unificata.

**Fase 3 — Range (5.0):** host Windows/Linux reali o VM, segmenti DMZ/corp/OT, scoring, after-action report, isolamento da VLAN/cloud; niente range prima che il Lab 4.2 sia verde.

**Effort e fasi (D9):** 14–18 gg per il Lab shadow (4.2), +6–8 gg per la regressione continua (4.3), +25–35 gg per il range multi-host (5.0). Il range completo è un epic da 6+ mesi di calendario, non una release: si costruisce sopra il Lab, non al posto suo. La stima 10–14 della v2.1 non includeva runner, asserzioni e UI dei run.

---
## 9. Modello dati e deployment

### 9.1 Nuove tabelle Aegis (migrazione 0020+)

```sql
-- 0020_api_keys: sostituisce la chiave globale (AEGIS-SEC-006)
CREATE TABLE api_keys (
  id            uuid PRIMARY KEY,
  name          text NOT NULL UNIQUE,
  key_hash      text NOT NULL,                 -- sha256, mai in chiaro
  scopes        text[] NOT NULL DEFAULT '{}',  -- {ingest:write, kraken:write}
  source        text,                          -- vincolo: questa chiave scrive solo qui
  created_by    uuid REFERENCES users(id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz,
  revoked_at    timestamptz
);

-- 0021_deception: eventi Kraken normalizzati (o riuso di siem_events con source=kraken; includere context lab/sensor in raw/mapping)
CREATE TABLE deception_sessions (
  id                uuid PRIMARY KEY,
  external_id       text NOT NULL UNIQUE,      -- session_id di Kraken
  node_id           text NOT NULL,
  sensor            text NOT NULL,             -- ssh|http|ftp|telnet|smb|rdp|...
  src_ip            inet NOT NULL,
  src_port          int,
  country           text,
  asn               int,
  first_seen        timestamptz NOT NULL,
  last_seen         timestamptz NOT NULL,
  command_count     int NOT NULL DEFAULT 0,
  credential_count  int NOT NULL DEFAULT 0,
  fingerprint       text,                      -- HASSH/JA3
  severity          text NOT NULL,
  campaign_id       uuid REFERENCES campaigns(id)
);

-- 0022_malware
CREATE TABLE malware_samples (
  sha256        text PRIMARY KEY,
  size_bytes    bigint NOT NULL,
  file_type     text,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL,
  yara_matches  text[] DEFAULT '{}',
  iocs          jsonb DEFAULT '{}',
  kraken_sample_id text,                      -- riferimento a Kraken; il file non entra mai in Aegis
  expires_at    timestamptz NOT NULL
);

-- 0023_ioc / campaigns / suppressions / canaries
CREATE TABLE iocs (id uuid PRIMARY KEY, type text NOT NULL, value text NOT NULL,
  source text NOT NULL, confidence int NOT NULL, first_seen timestamptz,
  last_seen timestamptz, tags text[] DEFAULT '{}', UNIQUE(type, value, source));
CREATE TABLE campaigns (id uuid PRIMARY KEY, name text, fingerprint text,
  first_seen timestamptz, last_seen timestamptz, description text);
CREATE TABLE suppressions (id uuid PRIMARY KEY, rule_id text NOT NULL, scope jsonb,
  reason text NOT NULL, created_by uuid, created_at timestamptz, expires_at timestamptz NOT NULL);
CREATE TABLE canaries (id uuid PRIMARY KEY, kind text, label text, token_hash text,
  deployed_at timestamptz, triggered_at timestamptz, trigger_count int DEFAULT 0);
```

Regole: ogni tabella nuova ha `created_at`, indice su `(source, occurred_at)`, e nessuna colonna con dati sensibili in chiaro (password, token).

### 9.2 Kraken: tabelle da aggiungere

```sql
nodes(id, node_id UNIQUE, name, key_hash, version, last_seen, config_applied_at, revoked_at)
sensors(id, node_id, name, port, enabled, last_event_at, status)
samples(sha256 PK, size, type, first_seen, yara jsonb, behavior jsonb, expires_at)   -- metadati; file su volume cifrato
attacker_fingerprints(id, hassh, ja3, first_seen, last_seen, session_count)
campaigns(id, name, fingerprint_id, first_seen, last_seen)
outbox(id, payload jsonb, attempts, next_attempt_at, status)   -- Postgres, stessa transazione dell'ingest; non Redis
```
E **rimozione** di `AttackEvent.password` in chiaro → `password_sha256`, `password_len`, `password_classes`.

Tabelle **Kraken Lab** (microservizio Kraken, non in Aegis DB): `lab_topologies`, `lab_networks`, `lab_hosts`, `lab_scenarios`, `lab_runs`, `lab_run_steps`, `lab_assertions`, `lab_evidences` (o equivalenti) con stato, hash definizione, finestra temporale, esiti/verdetti e riferimenti a eventi/alert correlati. Nessuna di queste tabelle nel Brain.

### 9.3 Deployment: compose del monorepo

Un `docker-compose.prod.yml` radice con profili:

```yaml
services:
  caddy:        { profiles: [prod], ... }                 # TLS, CSP, routing /kraken (UI+API dedicate) e /api,/ws Aegis
  aegis-brain:  { profiles: [prod], depends_on: [postgres, redis] }
  aegis-link:   { profiles: [prod] }
  frontend:     { profiles: [prod] }
  postgres:     { profiles: [prod, kraken], volumes: [pgdata] }
  redis:        { profiles: [prod, kraken] }
  kraken:       { profiles: [kraken], networks: [edge, kraken_internal], secrets: [...] }
  kraken-postgres: { profiles: [kraken] }
  sandbox-broker:  { profiles: [kraken], volumes: [/var/run/docker.sock:ro], networks: [kraken_internal] }
  # la rete sandbox è definita ma i container effimeri la creano a runtime con internal: true
networks:
  edge: {}
  kraken_internal: { internal: true }
```

Punti non negoziabili:
- `kraken` **non** monta il socket; solo `sandbox-broker`, che espone un'API allowlist.
- `sandbox-broker` non è raggiungibile da `edge`.
- Porte di DB, Redis, Grafana non pubblicate (`expose`, non `ports`).
- Ogni segreto con `:?` (nessun default).
- Healthcheck su tutti i servizi; `depends_on: condition: service_healthy`.

**K8s-ready senza Helm (D5/D10):** Brain, Link e frontend non scrivono su disco locale, non tengono stato di sessione in memoria e leggono tutta la configurazione da env/secret; Postgres e Redis restano esterni al pod; `/health` e `/ready` sono separati; shutdown con drain; immagini immutabili e non-root. Il chart Helm, i manifest e i test su kind arrivano **solo in 5.1**, quando esiste un cliente che li chiede. Non si aggiunge Kubernetes alla 4.x per "essere pronti": si evita di prendere decisioni che lo renderebbero impossibile.

### 9.4 Ordine di avvio e dipendenze

`postgres` → `redis` → `aegis-brain` (`alembic upgrade head` nell'entrypoint, idempotente) → `aegis-link` → `frontend` → `caddy`. Per il profilo kraken: `kraken-postgres` → `kraken` → `sandbox-broker`. Se `sandbox-broker` non è pronto, Kraken parte in modalità degradata (`SANDBOX_ENABLED=false`) e lo dichiara in `/health`.

---

## 10. Roadmap per release, feature per feature

Quattro release. Ogni voce ha: obiettivo, cosa si costruisce, dove, criterio di accettazione, effort, dipendenze. Le settimane sono **stime di lavoro** per un solo sviluppatore a 30 h/settimana (D16), non scadenze: il progetto è portfolio-first e non ha una data fissa. A 40 h si comprimono di circa il 25%, non del 50%. Con due persone si comprimono solo le parti frontend/backend in parallelo, non i gate di sicurezza.

---

### 4.1.0 — "Foundation + Kraken integration" (settimane 1–8, stima da ricalcolare)

**Tema:** rendere vere le cose già scritte e chiudere la verticale Kraken
end-to-end. Nessuna espansione del prodotto: solo il percorso minimo completo
che un analista può usare davvero. Cancello: tutto ciò che è in §6.1–6.3 verde.

**Scope utente (v2.7):** la 4.1 è la release in cui Kraken è realmente
integrato, non solo “avviabile”. Deve contenere: servizio nel compose,
contratto firmato con outbox/retry, UI Kraken raggiungibile, vista Aegis in sola
lettura e smoke test end-to-end. L'espansione (nuovi sensori, campagne, Lab,
timeline, ATT&CK) resta alla 4.2+.

#### 4.1.1 Kraken si avvia e ha una CI
- Obiettivo: `import`, migrazioni, test, immagine, pipeline.
- Dove: `services/kraken/app/db/session.py` (o annotazioni), `.github/workflows/ci.yml`.
- Accettazione: `pytest` 65/65 su GitHub; `alembic upgrade head` da DB vuoto; `docker build` verde; `ruff` pulito.
- Effort: 0,5 gg · Dipendenze: nessuna.

#### 4.1.2 Kraken non è più una privilege escalation
- Obiettivo: eliminare la classe di finding Critical (SEC-001, 002, 003, 006, 010).
- Dove: `endpoints/auth.py`, `schemas.py`, `docker-compose.yml`, `nginx/entrypoint.sh`, nuovo `deploy/sandbox-proxy/`.
- Accettazione: register non crea admin; il container app non vede `/var/run/docker.sock`; dalla sandbox `wget https://example.com` fallisce; compose senza `.env` non parte; senza certificato non serve TLS finto.
- Effort: 3 gg · Dipendenze: 4.1.1.

#### 4.1.3 Kraken non conserva più dati che non deve
- Obiettivo: password hashed, sample limitati, retention, backup cifrato.
- Dove: `models.py`, `attack_service.py`, `siem.py`, `telegram.py`, `docker_manager.py`, `scripts/backup.sh`, nuove migrazioni.
- Accettazione: ingest con password → nessun chiaro su DB/log/JSONL/Telegram; file 512 MB scartato; backup GPG + restore testato; retention 30 gg attiva.
- Effort: 2,5 gg · Dipendenze: 4.1.2.

#### 4.1.4 Aegis: integrità degli agenti
- Obiettivo: AEGIS-SEC-001, 002, 011, 007.
- Dove: `enroll.py`, `deploy.py`, `NodeTrace/agents/python/utils/curl_http.py`, `aegis-guard/.../Main.java`.
- Accettazione: re-enroll senza token → 409 con audit; agente installato da one-liner riceve e applica un update Ed25519; `ps` non mostra il device secret; `REMOVE_PERSISTENCE` rimuove solo il valore giusto e dichiara `failed` quando non rimuove nulla.
- Effort: 3 gg · Dipendenze: nessuna (può procedere in parallelo).

#### 4.1.5 Aegis: postura e DoS
- Obiettivo: AEGIS-SEC-004, 005, 006, 008, LOGIC-003/004/005.
- Dove: `total.py`, `config.py` (profili), `rate_limit.py`, `deps.py`, nuova `api_keys`, `playbook_engine.py`, `agent_deps.py`, `health.py`.
- Accettazione: zip bomb respinta senza crescita di RSS oltre il limite; due IP distinti hanno bucket distinti; chiave A non scrive su sorgente B e la revoca è immediata; `AEGIS_PROFILE=prod` con mTLS off non parte; coda comandi espone `commands_dropped`; revoca fail-closed; `/health` mostra la coda vera.
- Effort: 3 gg · Dipendenze: 4.1.4 (per la parte agenti).

#### 4.1.6 Aegis: CI verde
- Obiettivo: AEGIS-LOGIC-006/007/008/009, OPS-002/005.
- Dove: `tests/integration/test_siem_ingest.py`, `tests/conftest.py`, `requirements.txt`, `frontend/package.json`, `scripts/`.
- Accettazione: suite verde a qualunque data (test con `freezegun` a 2026-09-15, 2027-01-01, 2030-06-01); `pip-audit` 0; `npm audit --omit=dev` 0 high; job di restore notturno verde.
- Effort: 1,5 gg · Dipendenze: 4.1.5.

#### 4.1.7 Kraken → Aegis: consegna affidabile
- Obiettivo: il percorso firmato non perde eventi se Aegis è lento o spento.
- Dove: nuova tabella `outbox` in Kraken (stessa transazione dell'ingest),
  worker con backoff e jitter, `aegis_ingest.py`, migrazione Alembic, test.
- Accettazione: con Brain spento l'outbox cresce; al ritorno si svuota senza
  perdita; retry idempotente per `event_id`; HMAC errato → 401; evento vecchio
  → 422; 1.000 eventi in batch → 1.000 righe e 0 duplicati; `context=lab`
  distinto da `sensor`; metriche `outbox_pending`, `outbox_sent`,
  `outbox_failed` esposte.
- Stato 2026-11-15: implementato e verificato — outbox Postgres transazionale, worker con backoff, poison handling e stale recovery, prova live con Brain spento e ripresa, 130 test Kraken verdi.
- Effort: 3 gg · Dipendenze: 4.1.1, 4.1.2.

#### 4.1.8 UI Kraken e vista unificata Aegis
- Obiettivo: l'analista vede Kraken senza gestire due login separati, ma le
  operazioni Kraken-specifiche restano nella UI Kraken.
- Dove: routing Caddy `/kraken/*`, profilo compose, SSO delegato breve
  (`POST /api/v1/deception/token`), UI Kraken esistente, nuova pagina frontend
  Aegis in sola lettura, endpoint Brain per sessioni/eventi/incidenti collegati.
- Accettazione: Kraken raggiungibile dietro `/kraken/*`; login delegato
  funzionante e token breve non riutilizzabile; la SPA Aegis mostra eventi
  `source=kraken`, alert/incidente collegato e deep-link alla sessione Kraken,
  senza duplicare le operazioni Kraken; nessun dato in chiaro; asset UI
  (Tailwind, Chart.js, Leaflet) serviti localmente, senza dipendenza CDN, così
  la UI funziona anche in deploy air-gapped.
- Stato 2026-11-15: implementato e verificato — SSO monouso con chiave dedicata e assertion di 60 s, routing Caddy `/kraken/*`, asset vendorizzati e CSP senza JS inline, vista Aegis in sola lettura; smoke browser offline (2 test Playwright).
- Effort: 5 gg (3 routing/SSO Kraken + 2 vista Aegis) · Dipendenze: 4.1.7.

#### 4.1.9 Compose, configurazione e smoke test end-to-end
- Obiettivo: la verticale parte da un compose pulito, non dalla macchina dello
  sviluppatore.
- Dove: compose root con profilo `kraken`, `.env.example`, Caddy, documentazione
  di deploy, script di smoke test.
- Accettazione: `docker compose --profile kraken up` avvia Kraken, DB e broker
  senza socket montato nell'app; un attacco SSH su Kraken produce evento,
  alert/incidente e riga visibile in Aegis entro 10 s; restart di Brain o
  Kraken non perde eventi; la procedura è documentata e ripetibile da zero.
- Stato 2026-11-16: implementato e verificato — profilo `kraken` con Postgres/Redis/rete/init separati e broker sandbox unico titolare del Docker socket; `docker compose --profile kraken config` e `caddy validate` verdi; smoke live SSH→Brain con evento, alert e incidente; nessuna richiesta esterna dalla UI.
- Effort: 2 gg · Dipendenze: 4.1.7, 4.1.8.

**Definition of done 4.1.0**
- [ ] Nessun finding Critical/High aperto in §4 (esclusi quelli esplicitamente spostati a 4.2 con motivazione).
- [ ] `pytest` Aegis, 0 failed, 0 error, con e senza DB.
- [ ] Kraken: 65+ test verdi in CI, immagine che parte, privesc e pivot non riproducibili.
- [x] Kraken compare nel compose root con profilo dedicato e senza Docker socket nell'app.
- [x] Un attacco SSH su Kraken arriva in Aegis entro 10 s e resta idempotente al retry.
- [x] UI Kraken raggiungibile e vista Aegis in sola lettura funzionante; nessun secondo login obbligatorio.
- [x] `bandit` 0 High su entrambi (Kraken: 1 Medium B108 sul path tmpfs del container); `pip-audit` 0; `npm audit --omit=dev` 0 high.
- [x] Documento `SECURITY.md` aggiornato con la nuova postura.
- [x] Tag `v4.1.0`, release notes con tabella "prima/dopo".

**Stato 2026-11-16 (rilasciata):** Brain **823 passed, 3 skipped**; Kraken **130 passed**; Guard **140**; Link **17**; NodeTrace **58 passed, 2 skipped**; frontend lint **0 errori / 25 warning** e build OK; Playwright pagine **4/4** e verticale Kraken **2/2**; API smoke **ALL PASS**; bandit Brain **0 High**, Kraken **0 High** (1 Medium B108 su tmpfs), pip-audit **0**, npm audit **0 high**; compose e Caddy validi; smoke live SSO (exchange 200, replay 401) e ingest con Brain spento/ripreso (outbox `pending 0`, `sent`). Tag annotato `v4.1.0` a `17c499f`, CI del tag **verde** (`43916328707`), GitHub Release con 24 asset e smoke da download pulito (22 file, checksum OK). Restano fuori: firma cosign, SBOM per immagine e generazione CI del pacchetto Windows NodeTrace.

---

### 4.2.0 — "Kraken expansion & Unified SOC" (settimane 9–16, stima da ricalcolare)

**Tema:** dopo la verticale 4.1, Kraken si espande come sensore/lab e la SPA
Aegis guadagna la timeline unificata. La separazione dei servizi non cambia:
Kraken resta un microservizio con DB, UI e ciclo di rilascio propri.

#### 4.2.1 Kraken→Aegis: hardening del canale e replay
- Costruire: batch da 500, metriche outbox, replay degli eventi velenosi,
  allineamento di `deception_sessions`; il percorso base è già in 4.1.7.
- Dove: `aegis-brain/app/api/v1/ingest.py`, `app/ingest/kraken.py`,
  `services/kraken/app/services/outbox.py`.
- Accettazione: 1.000 eventi in batch → 1.000 righe, 0 duplicati al retry;
  evento con HMAC errato → 401; evento >7 giorni → 422; Kraken con Brain
  spento → outbox cresce e si svuota al ritorno, senza perdita; eventi
  `context=lab` accettati, marcati e distinguibili dai `sensor`.
- Effort: 2 gg · Dipendenze: 4.1.7.

**Gate di release:** la 4.2 non è la release che “collega Kraken”: quella
verticale è già in 4.1. Qui si aggiungono solo capacità dichiarate come
espansione, e nessuna può essere presentata come integrazione base.

#### 4.2.2 Regole di detection su deception
- Costruire: 6 regole Sigma nuove (`deception_ssh_bruteforce`, `deception_post_auth_commands`, `deception_credential_stuffing`, `deception_malware_download`, `deception_canary_trigger` — quest'ultima in 4.3, `deception_lateral_scan`), con `logsource: kraken`; correlazione `multi_sensor_same_ip`.
- Accettazione: replay su corpus Kraken sintetico → ogni regola ha almeno un positivo e un negativo; F1 resta 1.0 sul corpus Aegis; nessun alert per traffico scanner "solo banner".
- Effort: 2 gg · Dipendenze: 4.2.1.

#### 4.2.3 Timeline unificata (§7.3)
- Costruire: endpoint `timeline`, UI, unione di 5 sorgenti, virtualizzazione.
- Accettazione: p95 < 400 ms su 10k eventi; ordinamento corretto; link funzionanti.
- Effort: 3 gg · Dipendenze: 4.2.1.

#### 4.2.4 UI Kraken operativa estesa (campagne, sensori, Lab)
- **Kraken UI dedicata (`/kraken/*`, servizio Kraken):** campagne e
  fingerprint, sensori/nodi, topologie e run del Lab, sample, filtri e dettaglio
  operativo; la base (sessioni, comandi, mappa, vista Aegis) è già in 4.1.8.
- **Aegis SPA:** la vista unificata di base resta quella di 4.1.8; qui si
  aggiungono solo collegamenti a campagne e run Lab, senza duplicare la
  gestione operativa Kraken nel Brain/frontend Aegis.
- **Accettazione:** nessun dato in chiaro; campagne e run Lab visibili in UI
  Kraken; SPA Aegis mostra il collegamento senza esporre operazioni
  Kraken-specifiche; SSO delegato resta funzionante.
- Effort: 5 gg · Dipendenze: 4.1.8, 4.2.1.

#### 4.2.5 ATT&CK coverage (§7.4)
- Accettazione: matrice coerente con `coverage()`; buchi visibili; export.
- Effort: 2 gg · Dipendenze: nessuna.

#### 4.2.6 Soppressioni governate (§7.9)
- Accettazione: TTL obbligatorio; report mensile; alert alla scadenza.
- Effort: 2 gg · Dipendenze: nessuna.

#### 4.2.7 Flotta sensori Kraken (§8.2)
- Costruire: nodi, chiavi per nodo, config firmata, heartbeat, desired/applied.
- Accettazione: nodo compromesso non impersona altri; revoca immediata; nessun secret in chiaro.
- Effort: 3 gg · Dipendenze: 4.1.2 (broker) e 4.2.1.

#### 4.2.8 Nuovi sensori SMB e RDP (§8.1)
- Accettazione: SMB cattura hash NetNTLMv2 e file esca; RDP registra tentativi e banner; entrambi con health e metriche; nessuna implementazione di relay.
- Effort: 4 gg · Dipendenze: 4.2.7.

#### 4.2.9 Hardening mTLS reale (AEGIS-SEC-009) e Brain multi-worker (§7.10)
- Accettazione: header `X-Client-Cert` diretto rifiutato; 2 worker senza duplicati; p95 < 300 ms a 200 rps.
- Effort: 4 gg · Dipendenze: 4.1.5.

**Definition of done 4.2.0**
- [ ] La verticale 4.1 resta verde: attacco SSH → sessione UI Kraken, evento `siem_events`, alert/incidente, vista Aegis — entro 10 s.
- [ ] UI Kraken estesa a campagne, sensori e run Lab; la vista Aegis di base non viene duplicata.
- [ ] Nessuna doppia autenticazione per l'operatore (SSO delegato dove abilitato).
- [ ] Base Kraken Lab (topologia + scenario + run shadow) produce evidenze correlate in UI Kraken.
- [ ] Le 6 nuove regole hanno test di replay; load test documentato (200 rps, 2 worker).
- [ ] Tag `v4.2.0`.

---

### 4.4.0 — "Containment & Deception" (già 4.3.0)

> **Nota 2026-11-17:** questa sezione descrive la response originariamente
> pianificata per la 4.3.0. La 4.3.0 è ora l'agente unico Go; la response
> passa alla 4.4.0. I numeri 4.4.x qui sotto sono quelli correnti; 4.3.0
> resta il nome storico della response.

**Tema:** dalla visibilità all'azione, e Kraken da honeypot a piattaforma di deception.

#### 4.4.1 Contenimento di rete (§7.1)
- Costruire: connettori firewall/SG, `quarantine_host` con TTL, ripristino automatico, audit, kill switch.
- Accettazione: host isolato in <3 s su target simulato; ripristino a scadenza; nessuna azione senza TTL; audit a due campi (chi, perché).
- Effort: 5 gg · Dipendenze: 4.2.
- Rischio: un bug qui spegne la rete di un cliente → serve approvazione esplicita, TTL breve, dry-run di default in `pilot`.

#### 4.4.2 Contenimento credenziali (§7.2)
- Accettazione: disabilitazione con doppia approvazione su AD di test; audit; nessuna credenziale salvata.
- Effort: 4 gg · Dipendenze: 4.4.1 (stesso motore di azioni).

#### 4.4.3 Playbook come catalogo di azioni nominate
- Costruire: sostituire `script` (AEGIS-SEC-003) con azioni tipizzate (`isolate_host`, `block_ip`, `disable_account`, `quarantine_file`, `collect_forensics`, `notify`), parametri validati, dry-run, idempotenza per `(action, target, revision)`.
- Accettazione: nessun path raggiunge `subprocess` con input utente; grep test; dry-run non produce effetti.
- Effort: 3 gg · Dipendenze: 4.4.1/4.4.2.

#### 4.4.4 Detonazione, YARA e analisi sample (§8.3)
- Accettazione: ELF di test → hash, tipo, IOC, YARA; nessuna rete; timeout 120 s; sample mai eseguito dall'app.
- Effort: 6 gg · Dipendenze: 4.1.2/4.1.3.
- Rischio: alto (malware). Richiede container dedicato, `no-new-privileges`, seccomp, volume separato.

#### 4.4.5 Canary token e file esca (§8.5)
- Accettazione: apertura PDF → evento con `canary_id`, IP, user-agent; nessuna macro; distribuzione via agente.
- Effort: 3 gg · Dipendenze: 4.2.1.

#### 4.4.6 Risposta automatica su deception (§8.6)
- Accettazione: attacco high → incidente + playbook proposto + IP bloccato (target simulato) + audit, in <10 s.
- Effort: 2 gg · Dipendenze: 4.4.1, 4.4.5.

#### 4.4.7 Blocklist e export operativo (§8.7)
- Accettazione: 10k IP in <2 s, formati firewall, nessun IP privato, firma e versione.
- Effort: 2 gg · Dipendenze: 4.2.1.

#### 4.4.8 Report PDF unificato (§7.6)
- Accettazione: <5 s per 500 eventi; nessun dato sensibile; testo estraibile e testato.
- Effort: 3 gg · Dipendenze: 4.2.3.

#### 4.4.9 Alert routing e turni (§7.8)
- Accettazione: escalazione a T+15; ack ferma; MTTA in dashboard; canali Slack/Teams/webhook/PagerDuty-compat.
- Effort: 4 gg · Dipendenze: nessuna.

#### 4.4.10 Threat intel feed (§7.7)
- Accettazione: MISP/OTX/abuse.ch; cache 24 h; nessuna query per IP privati; degradazione silenziosa ma misurata.
- Effort: 4 gg · Dipendenze: 4.2.1.

#### 4.4.11 Dollhouse (§8.9)
- Accettazione: avvio <2 s, nessun file reale, watcher su file esca.
- Effort: 4 gg · Dipendenze: 4.4.4.

#### 4.4.12 Kraken Lab: scenari di verifica detection end-to-end (§8.12)
- Costruire: libreria di scenari riproducibili mappati a regole/tecniche Aegis, runner di run con asserzioni (alert/correlazione/risposta attesa entro T), correlazione con esiti Aegis via contratto, report evidenze in UI Kraken; modalità shadow di default.
- Accettazione: suite di scenari base eseguibile → report pass/fail/missed per asserzione con riferimenti a eventi/alert; nessuna azione distruttiva automatica in shadow; esecuzione confinata a reti lab isolate; risultati visibili in UI Kraken e riassunti nella vista unificata Aegis.
- Effort: 8 gg · Dipendenze: 4.2.1, 4.2.4, 4.4.4 (per scenari con sample).

**Definition of done 4.4.0**
- [ ] Una catena completa: scanner → brute force → login esca → comandi → download malware → canary → blocco IP + incidente + report PDF.
- [ ] Una suite Lab shadow produce evidenze pass/fail/missed sulla detection/risposta Aegis (senza fondere Kraken nel Brain).
- [ ] Ogni azione distruttiva ha TTL, dry-run e audit a due identità.
- [ ] Nessuna azione esegue comandi arbitrari sul server.
- [ ] Tag `v4.4.0`.

---

### 5.0.0 — "Platform + Range" (dopo la 4.4)

**Tema:** ciò che serve a un design partner o a un pilota che ha requisiti, non per convincere un tecnico. Da fare solo con almeno un design partner che lo chiede; senza trazione, si taglia lo scope, non la sicurezza.

#### 5.0.1 Identità e accesso aziendale
- OIDC/SAML (Entra ID, Okta, Keycloak), mapping gruppi→ruoli, SCIM per provisioning, MFA obbligatoria, sessioni con timeout e "termina tutte".
- Accettazione: login con Entra ID di test, mapping corretto, deprovisioning entro 1 min, audit di ogni cambio ruolo.
- Effort: 8–10 gg.

#### 5.0.2 Alta disponibilità vera
- Brain stateless, Redis Sentinel o cluster, Postgres con replica e failover, migrazioni senza downtime (expand/contract), readiness che esclude il nodo malato.
- Accettazione: uccidere un nodo sotto carico → 0 richieste perse, RTO < 60 s; migrazione con traffico attivo.
- Effort: 10 gg.

#### 5.0.3 Audit e compliance
- Audit immutabile (hash chain o WORM), export per revisore, retention configurabile, report SOC 2-ish (controlli, evidenze), DPA e registro trattamenti.
- Accettazione: manomissione di una riga di audit rilevata; export completo in <1 min per 100k righe.
- Effort: 6 gg.

#### 5.0.4 Intelligence e federation (§8.4/8.8)
- Campagne, fingerprint (HASSH/JA3), STIX/TAXII, MISP push, condivisione opzionale tra tenant (opt-in, anonimizzata).
- Effort: 8 gg.

#### 5.0.5 Performance e scala
- Obiettivi: 2.000 eventi/s in ingestione, 50k alert/giorno, 500 agenti, p95 API < 300 ms, retention 90 gg con partizioni e drop automatico.
- Come: batching, `COPY` per insert, partizioni mensili già presenti, indici rivisti, cache, worker separati per detection.
- Accettazione: benchmark con `k6` o `locust` documentato e riproducibile; nessuna regressione oltre il 10%.
- Effort: 8 gg.

#### 5.0.6 Estensibilità
- SDK playbook (Python) con azioni firmate, webhook in uscita con HMAC, API versionata con deprecation policy, plugin di detection in sandbox (nessun import arbitrario nel processo).
- Effort: 8 gg.

#### 5.0.7 Kraken Lab — Range v1 (D9)
- Costruire: host Windows/Linux reali o VM, segmenti DMZ/corp/OT, scoring, after-action report, isolamento da VLAN/cloud; sopra il Lab 4.2/4.3.
- Accettazione: scenario multi-host con 2 segmenti e 4 host; verdetto per asserzione; nessuna azione fuori dal lab; export del report.
- Effort: 25–35 gg · Dipendenze: 4.2.1, 4.2.4, 4.4.4, 4.4.12.
- Rischio: è un prodotto nel prodotto; se il tempo non c'è, si riduce lo scenario, non l'isolamento.

**Definition of done 5.0.0**
- [ ] Un design partner può fare login con il proprio IdP, ricevere un report per il revisore, e sopravvivere alla perdita di un nodo.
- [ ] Il range v1 esegue uno scenario multi-host con verdetto e report, senza uscire dal lab.
- [ ] Benchmark pubblico nel repo.
- [ ] Tag `v5.0.0`.

---

### 10.1 Riepilogo temporale

| Release | Settimane | Contenuto | Dipendenza critica |
|---|---|---|---|
| Gate 0 | 1 | licenza, `SECURITY.md`, release completa, privacy | nessuna (in parallelo) |
| 4.1.0 | 1–8 | fix bloccanti, CI verde, verticale Kraken completa (compose, outbox, UI, vista Aegis, smoke test) | nessuna |
| 4.2.0 | 9–16 | espansione Kraken (campagne, sensori, Lab), timeline, ATT&CK, soppressioni, flotta, SMB/RDP, base Lab shadow | 4.1 completa |
| 4.3.0 | 17–? | agente unico Go: parità Guard/NodeTrace, migrazione, installer, profilo router lab | 4.2 completa |
| 4.4.0 | ? | contenimento rete/credenziali, catalogo azioni, YARA/detonazione, canary, blocklist, PDF, routing, scenari Lab | 4.3 completa |
| 5.0.0 | ? | IdP aziendale, HA, audit/compliance, intel, performance, SDK, range v1 | un design partner o un pilota |

**Lettura onesta:** 52 settimane di lavoro stimate a 30 h/settimana (D16), già con un buffer per release; non sono 52 settimane di calendario né una scadenza. A 40 h/settimana il realistico è **37–43 settimane**; a 30 h/settimana **49–55**. Il totale delle voci è **187 giornate uomo (182–192)**: Gate 0 5 + 4.1 27 + 4.2 27 + 4.3 48 + 5.0 75–85. Sono ~37 settimane di lavoro puro a 5 giorni/settimana: ogni settimana in meno è una promessa non mantenuta, e con una data fissa sarebbe un debito. **La stima della 4.3 va rifatta:** il rewrite Go dell'agente unico non è compreso nelle 48 giornate della vecchia 4.3; il totale di 187 giornate non è più valido finché non viene ricalcolato.

### 10.2 Cosa può slittare senza rompere nulla
- 5.0.4 (federation) e 5.0.6 (SDK): utili, non urgenti.
- 5.0.7 (range): si può partire con 2 segmenti e 4 host; non si taglia l'isolamento.
- 4.4.11 (dollhouse) e 4.4.10 (feed): valore alto ma non bloccano il contenimento.
- 4.2.5 (ATT&CK) può andare in 4.4.

### 10.3 Cosa non può slittare
- Tutto 4.1.0, senza eccezioni: è il debito che rende falso ogni altro numero del prodotto.
- 4.2.1 (ingestione/contratto) e 4.2.4 (UI Kraken dedicata + vista unificata) se si vuole l'ecosistema a microservizi: senza, Kraken resta scollegato e la verifica detection via Lab non è dimostrabile end-to-end.
- 4.4.3 (catalogo azioni): finché `script` esiste, un admin può eseguire comandi sul server che custodisce la PKI.

---
## 11. Piano di test

### 11.1 Come ricostruire l'ambiente (comandi esatti, verificati)

> **Windows:** i comandi sotto sono POSIX. Usare WSL2 o Git Bash con una venv **Python 3.15**: con versioni EOL il pacchetto `jose` installato può non esporre `jwt` (`ImportError: cannot import name 'jwt' from 'jose'`) e la suite Kraken non parte. Non è un bug del progetto, è la versione sbagliata.

```bash
# --- Python ---
python3 -m venv .venv && . .venv/bin/activate
pip install -r aegis-brain/requirements.txt pytest pytest-asyncio pgserver redislite bandit pip-audit

# --- PostgreSQL 16 portabile ---
mkdir -p .work/pgdata
PG=.venv/lib/python3.15/site-packages/pgserver/pginstall/bin
$PG/initdb -D .work/pgdata -U postgres --auth=trust
$PG/pg_ctl -D .work/pgdata -o "-p 5432 -k /tmp -c listen_addresses=127.0.0.1" -l .work/pg.log start
$PG/createdb -h 127.0.0.1 -U postgres aegis_test
$PG/createdb -h 127.0.0.1 -U postgres aegis_migrate

# --- Redis 7 ---
.venv/lib/python3.15/site-packages/redislite/bin/redis-server --port 6379 --daemonize yes --save ""

# --- variabili per la suite ---
export DATABASE_URL='postgresql+asyncpg://postgres@127.0.0.1:5432/aegis_test'
export TEST_DATABASE_URL="$DATABASE_URL"
export REDIS_URL='redis://127.0.0.1:6379/0'
export REQUIRE_INTEGRATION=1 DEBUG=true

# --- Alembic (richiede l'intero set di secret + DEBUG=true) ---
cd aegis-brain && alembic upgrade head && alembic upgrade head   # seconda run idempotente

# --- Java ---
curl -L -o jdk.tgz 'https://api.adoptium.net/v3/binary/latest/21/ga/linux/x64/jdk/hotspot/normal/eclipse'
tar xzf jdk.tgz -C .work && export JAVA_HOME="$PWD/.work/jdk-25.0.5+8"
curl -L -o mvn.tgz 'https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz'
tar xzf mvn.tgz -C .work && export PATH="$PWD/.work/apache-maven-3.9.9/bin:$PATH"
```

### 11.2 Matrice dei test per area

| Area | Tipo | Comando | Criterio |
|---|---|---|---|
| Brain unit | unit | `pytest tests/unit -q` | 0 failed, 0 error |
| Brain integrazione | integration | `REQUIRE_INTEGRATION=1 pytest tests/integration -q` | 0 failed |
| Brain contratto API | contract | `pytest tests/test_openapi_contract.py` | 131 path invariati o migrati con nota |
| Detection | replay | `python scripts/replay_report.py --all` | F1 = 1.0, 0 FP |
| Sigma | engine | `python -c "...coverage()"` | 14/14 eseguibili |
| Guard | unit | `cd aegis-guard && mvn -B test` | 0 failure |
| Link | unit | `cd aegis-link && mvn -B test` | 0 failure |
| eBPF | contract | `python aegis-ebpf/tests/check-contract.py` | ALL PASS |
| Frontend | lint/tipi/build | `npm run lint && npx tsc -b --noEmit && npm run build` | 0 errori, build OK |
| SCA | audit | `pip-audit -r requirements.txt` + `npm audit --omit=dev --audit-level=high` | 0 |
| SAST | bandit | `bandit -r app -ll` | 0 High |
| Compose | config | `docker compose -f docker-compose.yml config -q` (+ prod) | exit 0 |
| Kraken | unit | `pytest services/kraken/tests/unit -q` | 65/65 (oggi 58 passed / 7 failed per LOGIC-005) |
| Kraken | integrazione | `pytest services/kraken/tests/integration -q` con PG+Redis | 0 failed |
| Kraken | isolamento | script `tests/security/test_isolation.sh` | rete sandbox `internal`, no socket, no egress |
| Privesc | sicurezza | `tests/security/test_register_admin.py` | 422/403 |
| Ingestione | e2e | `tests/e2e/test_kraken_ingest.py` | 1000 eventi, 0 duplicati, retry sicuro |
| Carico | perf | `k6 run tests/perf/ingest.js` | p95 < 300 ms a 200 rps |

### 11.3 Test che devono esistere e oggi non ci sono

1. **Regressione sul privesc** (`KRAKEN-SEC-001`): il test deve fare la richiesta esatta con `is_admin:true` e pretendere che l'utente risultante non sia admin. È il test più importante del progetto Kraken perché è l'unico che impedisce il ritorno del bug.
2. **Isolamento sandbox** (`KRAKEN-SEC-003`): test che ispeziona `docker network inspect` e verifica `Internal: true`, più un test funzionale che dalla sandbox tenta HTTP/DNS e fallisce.
3. **Socket assente** (`KRAKEN-SEC-002`): test che verifica l'assenza di `/var/run/docker.sock` e che il broker rifiuta `Privileged:true`.
4. **Password** (`KRAKEN-SEC-005`): ingest con password nota, poi grep su DB, log, JSONL, coda Telegram (mock) → nessuna occorrenza.
5. **Backup restore** (`KRAKEN-SEC-011`): in CI, dump cifrato → restore su DB vuoto → confronto conteggi tabelle e checksum.
6. **Re-enroll** (`AEGIS-SEC-001`): secondo enroll senza token → rifiutato; con token → ok + audit.
7. **OTA** (`AEGIS-SEC-002`): manifest firmato Ed25519 accettato; manifest HMAC con chiave diversa rifiutato; test end-to-end con l'agente Python.
8. **Secret in argv** (`AEGIS-SEC-011`): avvio agente, lettura `/proc/<pid>/cmdline`, assert che il token non compaia.
9. **REMOVE_PERSISTENCE** (`AEGIS-SEC-007`): su JVM con registry mock (o test Windows in CI matrice) verificare che venga rimosso un solo valore.
10. **Zip bomb** (`AEGIS-SEC-004`): payload 1:1000 con `RLIMIT_AS` e misura RSS; deve rispondere 422 senza OOM.
11. **Data-indipendenza della suite** (`AEGIS-LOGIC-006`): parametrizzare il test con `freezegun` su tre date lontane.
12. **Idempotenza ingestione Kraken** (`KRAKEN-LOGIC-001`): stesso `session_id` due volte → una riga, 200.

### 11.4 Cosa non è testabile in questo ambiente (e va dichiarato)
- **Docker runtime**: nessun daemon → `up`, isolamento reale, broker, sandbox: solo `compose config` qui; i test vanno eseguiti su una macchina con Docker (runner GitHub hosted ce l'ha).
- **Windows**: Guard e registry (`reg delete`) richiedono un runner `windows-latest`.
- **eBPF**: richiede kernel con BTF e privilegi; il contratto è testato, il runtime no.
- **Browser/e2e UI**: nessun browser in questo ambiente; i test Playwright vanno aggiunti in 4.2 con il runner CI.
- **Windows/AD**: i connettori di 4.3 vanno testati su un lab (AD DS in VM) o con mock.

---

## 12. CI/CD target

### 12.1 Job per il monorepo

```yaml
name: ci
on: [push, pull_request]
jobs:
  brain:        # python 3.15, services postgres:16 + redis:7
    steps: [lint(ruff), mypy --ignore-missing-imports, pytest -q --cov, bandit -ll, pip-audit]
  guard:        # temurin 21
    steps: [mvn -B verify, spotbugs (soft)]
  link:         # temurin 21
    steps: [mvn -B verify]
  ebpf:         # ubuntu, clang, libbpf
    steps: [make, check-contract.py]
  frontend:
    steps: [npm ci, lint, tsc --noEmit, build, npm audit --omit=dev --audit-level=high]
  kraken:       # services postgres:16 + redis:7 (+ docker per i test di isolamento)
    steps: [ruff, mypy (soft), pytest -q, bandit -ll, pip-audit]
  security:
    steps: [trivy fs --severity HIGH,CRITICAL, gitleaks, semgrep (soft)]
  compose:
    steps: [docker compose config -q, docker compose -f docker-compose.prod.yml config -q,
            docker build ., docker build services/kraken]
  e2e:          # solo su main, con docker
    steps: [compose up -d, smoke-test.sh, playwright test, compose down -v]
```

Regole:
- **Nessun gate `continue-on-error`** su security e test. Oggi ce ne sono su alcuni punti: vanno rimossi progressivamente con la stessa PR che corregge i finding.
- **Pinning per SHA** delle action (già fatto in Aegis: mantenerlo).
- **Cache** per pip/npm/maven per stare sotto i 10 minuti.
- **Nightly**: restore test, `pip-audit`, `trivy`, e2e completo, benchmark.

### 12.2 Release
- Tag semver, `CHANGELOG.md` generato dai PR label, SBOM (CycloneDX) allegato, immagini firmate (cosign), `docker-compose.prod.yml` con digest pinnati (non `:latest`).
- Firma degli artefatti con la stessa chiave Ed25519 del prodotto? **No**: chiave di release separata da quella degli agenti (lezione di AEGIS-SEC-002).

---

## 13. Sicurezza operativa e runbook

### 13.1 Segreti: dove vivono

| Segreto | Dove | Rotazione | Chi può leggerlo |
|---|---|---|---|
| `SECRET_KEY` (JWT) | env / secret file | 90 gg, con doppia validità | brain |
| `AGENT_ENROLL_KEY` | secret file 0400 | 180 gg | brain (per emettere token) |
| `AGENT_SIGNING_KEY` (Ed25519) | file 0400, offline | 1 anno | brain |
| api key per fonte | DB, hash | 90 gg | nessuno in chiaro |
| `KRAKEN_INGEST_SECRET` | secret file | 90 gg | brain + kraken |
| device secret | solo DB hash + host | su re-enroll | agente |
| `BACKUP_PASSPHRASE` | secret file | 1 anno | job di backup |

### 13.2 Runbook essenziali (da scrivere in `docs/runbooks/`)

1. **Agente compromesso**: revoca (subito, fail-closed) → rotazione enroll key se sospetta → raccolta forense dal DB → ricerca eventi dello stesso `agent_id`.
2. **Brain compromesso**: isolare il nodo → ruotare `SECRET_KEY`, chiavi PKI, api key → invalidare sessioni → verificare integrità audit → notifica.
3. **Kraken compromesso**: spegnere i sensori → revocare chiavi nodo → preservare i sample per l'analisi → ricostruire l'immagine → verificare che il broker non sia raggiungibile da `edge`.
4. **Malware "escapato" dalla sandbox**: kill del container, snapshot del volume, analisi dell'immagine, verifica delle regole iptables del broker, review dei log del daemon.
5. **Perdita di un backup**: verificare cifratura, valutare notifica GDPR (72 h), ruotare passphrase.

### 13.3 Checklist prima di esporre su Internet

- [ ] `AEGIS_PROFILE=prod` (mTLS required, strict, registrazione chiusa).
- [ ] `RATE_LIMIT_STORAGE_URI` su Redis e `TRUST_FORWARDED_FOR=true` solo dietro proxy.
- [ ] Caddy con TLS valido, HSTS, CSP; nessuna porta di servizio pubblicata.
- [ ] `POSTGRES_PASSWORD`/`REDIS_PASSWORD`/`GRAFANA_PASSWORD` senza default.
- [ ] Kraken: nessun socket, rete sandbox/lab `internal`, register off, TLS non auto-generato, run lab marcati `context=lab` e shadow di default.
- [ ] Backup cifrato + restore provato negli ultimi 7 giorni.
- [ ] Audit attivo, retention configurata, `RETENTION_REQUIRE_BACKUP=true`.
- [ ] Log senza segreti (grep su `password`, `token`, `Authorization` nei log di 24 h).
- [ ] `pip-audit` e `npm audit` a 0; immagini scansionate.

---

## 14. Rischi, decisioni e cose da non sbagliare

| # | Rischio | Probabilità | Impatto | Mitigazione |
|---|---|---|---|---|
| 1 | Il fix di Kraken è "solo 1 riga" e si sottovaluta il resto | Alta | Alto | cancello A/B espliciti, nessun merge senza privesc test |
| 2 | Il broker sandbox introduce una nuova superficie | Media | Alto | allowlist stretta, niente `exec` arbitrario dall'esterno, test di `Privileged:true` |
| 3 | La deception produce rumore e il SOC la spegne | Alta | Medio | regole con negativi nel corpus, soppressioni con TTL, dashboard precisione |
| 4 | Il contenimento di rete spegne un host di produzione | Media | Critico | TTL breve, dry-run di default in pilot, doppia approvazione, audit |
| 5 | La detonazione malware diventa il buco più grande | Media | Critico | container dedicato, no rete, no socket, seccomp, volume separato |
| 6 | Il monorepo diventa un container di servizi che nessuno aggiorna | Media | Alto | un solo compose, un solo `make`, CI che builda tutto |
| 7 | La roadmap si allarga e la 4.1 non esce | Alta | Alto | 4.1 = solo fix; nessuna feature ammessa |
| 8 | Il cliente chiede multi-tenant e si accetta | Media | Alto | risposta scritta: 5.0+, con stima |
| 9 | Si vende senza licenza o senza privacy/DPA | Alta | Critico | Gate 0 prima di ogni pilot; revisione legale |
| 10 | Si svende il prodotto come SIEM generalista e si perde la nicchia | Alta | Alto | posizionamento SOC-in-a-box + deception/Lab; nessun confronto con vendor esterni |
| 11 | Bus factor 1: una persona, 187 giornate (182–192), nessun margine | Alta | Alto | buffer 20%, documentazione operativa, primo collaboratore su frontend/QA |

**Decisioni chiuse (v2.3, D16 aggiornata in v2.4, D17 in v2.7):** D1 AGPL-3.0-only; D2 mid-market multi-superficie; D3/D4 visibilità, non vendita; D5 Compose + K8s-ready; D6 Aegis root + `services/kraken`, push/subtree solo su autorizzazione; D7 `script` rimosso; D9 Lab a fasi; D10 Helm 5.1; D11 soglie; D12 AI locale; D13 single deployment; D14 ISO dopo 4.1; D15 nessun vendor nominato; D16 30 h/settimana, portfolio-first, nessuna data fissa; D17 verticale Kraken completa in 4.1, espansione in 4.2+.

**Restano da fare tu:** autorizzare il push di `7fd50a9` e il subtree; confermare il nome pubblico (Aegis è molto conteso); decidere se serve un tutore/legale per licenza e privacy da minorenne.

---

## 15. Prossimi 7 / 30 / 90 giorni

**7 giornate di lavoro (≈10 giorni di calendario a 30 h)**
- Giorno 1: Gate 0 — `LICENSE` AGPL, `NOTICE`, `TRADEMARK.md`, `SECURITY.md`, `CONTRIBUTING.md`; **chiedi autorizzazione** per push e subtree. Se arriva il sì: push, subtree, import/Alembic. Se no: Kraken resta fermo e si passa a Gate C.
- Giorno 2: KRAKEN-SEC-001 (privesc) con test di regressione; KRAKEN-SEC-007.
- Giorno 3: KRAKEN-SEC-002 broker socket-proxy (prima versione allowlist).
- Giorno 4: KRAKEN-SEC-003 rete `internal` + test di isolamento.
- Giorno 5: KRAKEN-SEC-005 password hashed + redaction.
- Giorno 6: AEGIS-LOGIC-006 (data-bomb) + 007; CI Aegis torna verde.
- Giorno 7: AEGIS-LOGIC-008/009, AEGIS-OPS-005; `pip-audit`/`npm audit` a 0.

**30 giorni di calendario (≈4,5 settimane)**
- Gate 0 chiuso; Gate A sbloccato solo con autorizzazione; Gate B in corso. La 4.1 non è ancora taggata: serve la settimana 5–6.
- Scrivere `SECURITY.md` (fatto), `docs/runbooks/` (5 runbook), e i 12 test di §11.3.
- Provare l'intero compose su una macchina con Docker: `up`, smoke test, backup+restore.
- Non iniziare la 4.2 prima che la 4.1 sia taggata.

**90 giorni di calendario (≈13 settimane)**
- 4.1 taggata; 4.2 in corso (ingestione, timeline, UI Kraken), non completa: la 4.2 finisce intorno alla settimana 15–16.
- 4.3 non avviata: dipende dalla 4.2.
- Un pilot interno con 3 host e 1 nodo Kraken, con numeri misurati (MTTD, MTTA, alert/day), se la 4.2.1 è stabile.

---

## 16. Mappa dei file (dove mettere le mani)

### Aegis — i 20 file che contano

| File | Perché |
|---|---|
| `aegis-brain/app/main.py` | composizione app, router, lifespan, worker |
| `aegis-brain/app/core/config.py` | tutti i flag di postura (profili, mTLS, rate limit) |
| `aegis-brain/app/core/deps.py` | auth, ruoli, api key |
| `aegis-brain/app/core/agent_deps.py` | autenticazione agente, revoca (fail-open) |
| `aegis-brain/app/core/health.py` | liveness/readiness, chiave coda sbagliata |
| `aegis-brain/app/core/rate_limit.py` | storage e FFP |
| `aegis-brain/app/api/v1/enroll.py` | re-enroll (SEC-001) |
| `aegis-brain/app/api/v1/deploy.py` | installer, firma (SEC-002) |
| `aegis-brain/app/api/v1/telemetry.py` | ingestione agenti, isolate |
| `aegis-brain/app/api/v1/ingest.py` | ingestione shipper/kraken (SEC-006) |
| `aegis-brain/app/api/v1/total.py` | decompressione (SEC-004) |
| `aegis-brain/app/services/playbook_engine.py` | azioni, coda, idempotenza |
| `aegis-brain/app/services/detection*.py` + `sigma/` | regole |
| `aegis-brain/app/ingest/base.py` | contratto `UnifiedEvent` (riuso per Kraken) |
| `aegis-brain/requirements.txt` | SCA |
| `aegis-guard/src/main/java/com/aegis/guard/Main.java` | remediation (SEC-007) |
| `NodeTrace/agents/python/utils/curl_http.py` | secret in argv (SEC-011) |
| `frontend/vite.config.ts` + `package.json` | build, audit |
| `docker-compose.prod.yml` + `Caddyfile` | postura di deploy |
| `.github/workflows/ci.yml` | gate |

### Kraken — i file che contano

| File | Perché |
|---|---|
| `app/db/session.py` / `app/models/models.py` | blocker di avvio, password in chiaro |
| `app/api/v1/endpoints/auth.py` | privesc, refresh |
| `app/api/v1/endpoints/containers.py` | sandbox, blacklist |
| `app/services/docker_manager.py` | socket, rete, sample |
| `app/services/attack_service.py` | ingestione, idempotenza |
| `app/core/config.py` | segreti, validazione |
| `app/core/metrics.py` | cardinalità |
| `docker-compose.yml` | socket, reti, segreti |
| `nginx/entrypoint.sh` | TLS finto |
| `scripts/backup.sh` | backup rotto |
| `scripts/secure_sandbox.sh` | egress permesso |
| `honeypot/sensors/*` | nuovi sensori |

### Dove mettere i nuovi file

```
docs/archive/PLAN_AEGIS_KRAKEN_HANDOFF.md      # questo documento
SECURITY.md                             # postura, minacce, modello
docs/runbooks/{agent,brain,kraken,malware,backup}.md
docs/adr/0001-kraken-as-service.md      # decisione di §5.1
docs/adr/0002-event-contract.md         # decisione di §5.3
services/kraken/                        # il servizio nel monorepo
tests/security/                         # test di sicurezza eseguibili
```

---

## 17. Glossario minimo

| Termine | Significato nel progetto |
|---|---|
| **Agente** | Guard (Java) o NodeTrace (Python) installato su un endpoint |
| **Brain** | API/centro di controllo Aegis |
| **Link** | collector Spring che accoda eventi su Redis |
| **UnifiedEvent** | contratto normalizzato eventi (`app/ingest/base.py`) |
| **Sigma** | formato di regola di detection, eseguito dall'engine interno |
| **Correlazione** | regole multi-evento che producono alert composti |
| **Playbook** | catena di azioni su un alert/incidente |
| **Enroll** | registrazione di un agente e consegna del device secret |
| **mTLS** | mutual TLS, qui implementato via header verificati |
| **Deception** | honeypot e esche (Kraken) |
| **Sandbox** | container effimero dove l'attaccante esegue comandi |
| **Broker** | proxy che media l'accesso al Docker socket (da costruire) |
| **Kraken Lab** | ambiente di test/deception nel microservizio Kraken (topologie/sottoreti, scenari, run, evidenze) per verificare detection Aegis |
| **Canary** | esca che genera un evento quando viene toccata |
| **HASSH / JA3** | fingerprint di client SSH / TLS |
| **MTTD / MTTA** | tempo medio a rilevare / a riconoscere |

---

## 18. Ultima pagina: cosa fare appena apri la sessione

```bash
git checkout dev && git pull
python -c "import sys; print(sys.version)"   # 3.15
sed -n '1,60p' docs/archive/PLAN_AEGIS_KRAKEN_HANDOFF.md   # questo documento
# 1. NON pushare e NON fare subtree senza autorizzazione esplicita.
#    Chiedi: "Posso pushare 7fd50a9 su origin/main e importare con subtree?"
#    Solo dopo il sì, nel repo Kraken: git push origin main
#    Poi, nel monorepo:
# git subtree add --prefix services/kraken ../kraken main
#    Nota: subtree add crea un commit.
cd services/kraken && python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt && python -c "import app.main"   # deve funzionare su 7fd50a9
# 2. chiudi KRAKEN-LOGIC-005 (tmp_path) e scrivi il test del privesc PRIMA del fix
# (il subtree si esegue una sola volta; se esiste già, saltare)
# 3. KRAKEN-SEC-001 + KRAKEN-SEC-008 (CI) + ruff: Gate A verde
# 4. apri la PR "fix(kraken): bootable service, no privilege escalation, CI"
```

Regola finale: **nessuna feature, nessun refactor estetico, nessuna nuova dipendenza** finché il cancello A non è verde. Tutto il resto di questo documento presuppone che Kraken parta e che Aegis abbia la CI verde: senza quelle due cose, ogni riga successiva è una promessa non verificabile.

---

## Appendice A — Decisioni chiuse (D1–D17)

> Chiuse il 2026-11-13. Non sono più opzioni: sono vincoli di lavoro. Ogni modifica futura che le contraddice richiede una nuova decisione scritta.

| ID | Decisione | Perché | Conseguenza operativa |
|---|---|---|---|
| D1 | **AGPL-3.0-only** + `NOTICE` + policy sul marchio; niente EULA/CLA da minorenne | visibilità, copyleft di rete, attribuzione; nessun contratto negoziato | Gate 0; SPDX nei file nuovi; niente tier open-core per ora |
| D2 | **Mid-market e ambienti grandi**; Windows/Linux ora, macOS 5.x, router OpenWrt 4.3 lab, sensori di rete 4.2 | il valore è coprire endpoint e rete, non solo PC | matrice §2.4; Android/iOS solo 5.x via MDM |
| D3 | **Visibilità, non vendita diretta**: community, demo, contenuti | a 17 anni il ritorno utile è reputazione e adozione | README/demo; canali community |
| D4 | **Niente prezzo, listino o billing**; sponsorship solo dopo trazione | il prodotto non è in vendita e non deve sembrare un'offerta commerciale | nessuna pagina prezzi; niente fatturazione nel codice |
| D5 | **Compose 4.x** è il deployment supportato; architettura K8s-ready da subito | semplicità oggi, senza chiudere la porta ai clienti grandi | §9.3; niente manifest K8s nella 4.x |
| D6 | **Aegis alla root + `services/kraken`**; move in `aegis/` solo dopo Gate A; push/subtree solo su autorizzazione | evitare 400+ path rotti e storia riscritta | §6.1; il subtree crea un commit |
| D7 | **Rimuovere `script`** in 4.1; catalogo di azioni nominate in 4.3 | elimina l'esecuzione arbitraria sul Brain | AEGIS-SEC-003; grep test su `subprocess` |
| D8 | **Nessuna priorità**: ordine del piano | tutte le feature della 4.2 servono | §10.2 |
| D9 | **Lab a fasi**: shadow 4.2 → regressione 4.3 → range multi-host 5.0 | il range completo è 6+ mesi, non una release | §8.12; niente range prima del Lab verde |
| D10 | **Helm 5.1**, solo su richiesta documentata | 8–10 gg e matrice di test che oggi non serve | §5.4; niente Helm nella 4.x |
| D11 | **Soglie + Redpanda/NATS prima di Kafka** | Kafka a 10³–10⁵ eventi/giorno è costo senza beneficio | §5.4 |
| D12 | **Ollama locale default**, cloud opt-in con chiave del cliente | dati in sede, air-gap; nessun dato che esce da solo | §7.11; AI mai nel contenimento |
| D13 | **Un deployment per cliente**, `tenant_id` predisposto | isolamento e backup semplici; MSSP non è il target iniziale | §5.4; multi-tenant solo 5.0 |
| D14 | **ISO 27001 dopo la 4.1**, DPA e registro subito | credibilità presso i clienti senza bruciare 6–12 mesi ora | Gate 0 privacy; niente SOC 2/ACN senza partner |
| D15 | **Flank mid-market** con SOC-in-a-box + deception/Lab; nessun vendor nominato | si vince sul tempo al valore, non sulla scala SIEM | nessun confronto in codice, doc, commit o marketing |
| D16 | **30 h/settimana**, portfolio-first, nessuna data fissa; 4.1 ~9 settimane di lavoro, roadmap 49–55 stimate | il progetto è un biglietto da visita, non una consegna contrattuale; sostenibilità e qualità | §6.4, §10; 40 h solo in vacanza; stime aggiornate quando la realtà cambia |
| D17 | **4.1 = verticale Kraken completa** (compose, outbox, UI, vista Aegis, smoke test); espansione in 4.2+ | evita una release “Kraken avviabile” e una UI promessa alla release dopo | §4.1.7–4.1.9, §10.1, `docs/RELEASES.md`; le stime si spostano, non si riducono |

### A.1 Cosa non è negoziabile

1. Nessun commit e nessun push senza un «sì» esplicito. Vale anche per `git subtree add`, che crea un commit.
2. Un finding = una PR, con test di regressione che fallisce prima e passa dopo.
3. Nessuna feature prima che Gate A sia verde (Kraken parte, test verdi, CI su GitHub).
4. Nessun nome di vendor o prodotto usato come benchmark interno in codice, documenti, commit, issue o marketing.
5. Niente attribuzione ad AI e niente co-autore nei commit.
6. Android/iOS non sono supportati nella 4.x; senza MDM ed entitlement sarebbero una promessa falsa.
7. Kubernetes/Helm non entrano nella 4.x; l'architettura è K8s-ready, il deployment no.
8. Il range multi-host non inizia prima che il Lab 4.2 sia verde e che il containment 4.4 abbia TTL, dry-run e audit.

---

## Appendice B — Regole di lavoro e commit

### B.1 Commit

- Formato: `tipo(scope): descrizione` — es. `fix(kraken): enforce is_admin=false on register`, `docs(plan): close D1-D16`, `test(kraken): cover privilege escalation`, `feat(lab): add shadow scenario runner`.
- Tipi ammessi: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `perf`, `ci`, `build`. Un commit = un tipo.
- Niente nomi di vendor/prodotti usati come riferimento interno, niente co-autore, niente trailer o footer che citino AI.
- Il messaggio dice **perché**, non solo cosa. Se il commit chiude un finding, cita l'ID (`KRAKEN-SEC-001`), non il nome del vendor.
- Nessun CLA; il contributo è rilasciato sotto AGPL-3.0-only.

### B.2 Push e PR

- **Mai** `git push`, `git subtree add`, force-push o tag senza autorizzazione esplicita.
- Prima di chiedere: mostra `git status --short`, il diff stat, i test eseguiti e il rischio residuo.
- Una PR per finding; niente refactor estetico nello stesso diff. Se serve un refactor, PR separata e motivata.
- Branch: `fix/<finding>`, `feat/<scope>`, `docs/<scope>`, `test/<scope>`.

### B.3 Definition of done di una PR

- [ ] Il test di regressione fallisce sul codice vecchio e passa sul nuovo.
- [ ] I test pertinenti sono verdi; nessun test skippato o indebolito per far passare la PR.
- [ ] `ruff`/`bandit`/`pip-audit` (o l'equivalente del componente) non peggiorano.
- [ ] Doc aggiornata se cambia un contratto, un default o una procedura.
- [ ] Nessun segreto, nessun dato reale, nessun sample malware nel diff.
- [ ] Il messaggio di commit è conforme a B.1.

### B.4 Come chiedere l'autorizzazione

Template:

```text
Sto per creare il commit: <tipo(scope): messaggio>
File: <elenco>
Test: <comandi + esito>
Rischio residuo: <...>
Posso committare? Posso pushare su <remote/branch>?
```

Senza una risposta affermativa, il lavoro resta locale e non si pusha.

### B.5 PR, merge e release

**Modello:** GitHub Flow, non un `dev` di lunga durata. `main` è sempre verde e rilasciabile; ogni modifica nasce da un branch corto e rientra con una PR. `dev` resta solo come integrazione temporanea o viene ritirato: due branch lunghi che divergono sono la causa dei merge enormi.

**Aegis oggi:** `dev` è 2 commit avanti (documenti) e `main` è 6 avanti (merge e fix): sono divergenti. La prima PR dopo la review unisce i documenti a `main`; poi `dev` si ritira o resta solo per una release candidate. Non si continua a lavorare su due branch paralleli.

**Ciclo di una modifica:**
1. Ticket (GitHub Issue o il tracker che usi) con criterio di accettazione.
2. Branch da `main`: `fix/<finding>`, `feat/<scope>`, `docs/<scope>`, `test/<scope>`.
3. Commit piccoli e coerenti; il test di regressione viene prima del fix.
4. PR verso `main`, anche in auto-review: diff, CI, rischio, rollback.
5. Squash merge: una PR = un tipo = un commit su `main`; il titolo della PR è il messaggio Conventional Commit.
6. Branch cancellato; ticket chiuso con `Closes #...`.

**Dimensione:** una PR dovrebbe stare sotto ~400 righe di diff. Se è più grande, si spezza per strati (test, fix, UI, docs) o si usa una feature branch con più PR piccole. Una PR da 3.000 righe non è review, è speranza.

**Merge:** squash per default (storia lineare, un commit per PR). Merge commit solo per una release o per un branch che deve restare riconoscibile. Rebase solo in locale, mai su `main` condiviso. Niente force-push su `main`. Su GitHub: branch protection su `main` (PR obbligatoria, CI verde, storia lineare, no force-push); anche da solo è il punto in cui il CI ti impedisce di mentire a te stesso.

**Feature lunghe:** dietro flag, così `main` resta rilasciabile. Non si tiene un branch aperto per settimane.

**Release:**
- Scope-based, non "quando tutto è pronto": si taglia quando un milestone è coerente e verde. In azienda si usa spesso un release train (es. ogni 2 settimane): si taglia ciò che è pronto, il resto slitta. Per un solo sviluppatore il treno è il milestone, non il calendario.
- `CHANGELOG.md` (Keep a Changelog) aggiornato nella PR: Added / Changed / Fixed / Security / Removed.
- PR `chore(release): 4.1.0` che aggiorna versione, changelog e note di upgrade; CI completa; poi tag `v4.1.0` e GitHub Release.
- La release si costruisce **dal tag**, non dal branch; artefatti, SBOM, checksum e firma allegati; smoke test dagli artefatti.
- Hotfix: branch dal tag, `fix/...`, patch `4.1.1`, poi back-merge su `main`.
- SemVer: MAJOR solo per un cambio incompatibile del contratto pubblico; MINOR per feature retrocompatibili; PATCH per fix. Un security fix è PATCH, non un nuovo major. La rimozione di `script` in 4.1 è hardening di una funzione disabilitata di default: va scritta in `UPGRADING.md`, non trasforma la release in un major.

**Regola per Aegis:** il numero non è marketing. Oggi i tag v1–v4 sono batch con release incomplete (solo il jar di Guard): prima di alzare il numero, la release deve essere installabile e completa (AEGIS-REL-002). Meglio una 4.1.0 vera che una 5.0.0 vuota.

**Tag pubblicati:** i tag `v1.0.0`–`v4.0.0` esistono su `origin` e hanno una GitHub Release. Non si cancellano, non si spostano e non si riusano: una versione pubblicata è un fatto, anche quando la release era incompleta. Il tag locale `v4.0.0` punta a `de52206`, quello remoto a `38e245f`: è un disallineamento locale, non una licenza per riscrivere il remoto. La release successiva resta **`v4.1.0`**, e si tagga solo dopo Gate 0 e AEGIS-REL-002. La mappatura e l'audit sono in `docs/RELEASES.md`; il changelog è `CHANGELOG.md`.

**Versioni nel codice:** i campi versione restano `4.0.0` fino alla PR di release; non si bumpano a mano in una PR di feature. La PR `chore(release): 4.1.0` aggiorna Brain, frontend, Guard, NodeTrace, OCSF e `pack-artifacts.py` insieme, poi crea un tag annotato da `main`.
