# Changelog

All notable changes to Aegis Ecosystem are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Semantic Versioning applies to releases after `v4.0.0`. The older tags
`v1.0.0`–`v4.0.0` were batch labels, not complete SemVer releases; they remain
published and are not rewritten. See [docs/RELEASES.md](docs/RELEASES.md) for
the tag audit and the release policy.

> A published version is immutable. `v4.1.0` is the first complete release
> after the batch tags: the full Kraken vertical ships with the hardening
> fixes, and expansion moves to 4.2+.

## [4.3.0] - 2026-11-23

### Packaging server e persistenza (2026-11-22)

- `ak update` non e' piu' interattivo: apt/dpkg girano con
  `DEBIAN_FRONTEND=noninteractive` e `--force-confdef`/`--force-confold`, quindi
  un aggiornamento remoto non si blocca su una domanda debconf e non riscrive
  `server.env`/`kraken.env`. Trovato testando 4.3.0 -> 4.3.1 in un container.
- `ak start --wait` (con `--timeout`, default 300s per componente) attende che i
  container siano running e senza health `starting`/`unhealthy`; su Windows il
  comportamento era gia' `compose up --wait` e ora accetta gli stessi flag.
- `ak doctor` riporta il budget memoria: RAM host, limite dell'engine Docker, uso
  per container e, dentro WSL, il promemoria che il numero e' il tetto della VM e
  non il consumo di Aegis.
- CI: job `release_assets` sui tag `v*` che attende la release creata da `ci.yml`
  e allega i pacchetti con i checksum, senza mai sovrascrivere un asset
  pubblicato; la validazione MSI sopprime solo `ICE61` (downgrade voluto) e
  mantiene attivi gli altri ICE.

- Aggiunti i pacchetti completi `aegis` (Brain, Link, dashboard/frontend,
  PostgreSQL, Redis, Caddy, backup) e `kraken` (app, sensori, broker, RDP,
  database e Redis privati), più il meta-pacchetto `aegis-suite` e il bundle
  `aegis-suite-<version>.tar.gz` per scaricare entrambi gli stack insieme. Ogni
  stack conserva il proprio file systemd, i propri segreti in `/etc/aegis/*.env`
  e il proprio ciclo di vita; l'agente MSI/deb resta solo endpoint e il bundle
  non lo installa sul server.
- `aegis-suite` non è solo un elenco di dipendenze: il suo post-install crea la
  rete condivisa `aegis_shared`, allinea i segreti SSO/ingest, punta Kraken a
  `aegis-brain:8000`, abilita l'integrazione e serve la UI sotto `/kraken/`.
  Installare i due pacchetti separatamente non li collega.
- Aggiunto il comando operativo `ak`, esposto da entrambi i pacchetti server
  tramite `update-alternatives` senza conflitti di file: `ak start/stop/restart`
  gestiscono systemd, mentre `ak status/ps/logs/doctor/url` mostrano lo stato
  reale di unit e container. `ak configure` cambia hostname pubblico, email ACME,
  URL pubblico e porta locale senza riscrivere i segreti. `ak --help` e
  `ak help <command>` sono la documentazione locale; il server resta headless e
  non crea un'icona desktop. Riferimento completo in `docs/AK_CLI.md`.
- La dashboard non è più cablata alla porta host 3000: `AEGIS_UI_PORT` è
  configurabile, il pacchetto sceglie automaticamente il primo slot libero in
  `3000-3099` se la porta richiesta è occupata e registra il valore in
  `/etc/aegis/server.env`. L'installazione `aegis` usa debconf per dominio,
  email ACME e porta; gli stessi valori sono preseedabili via ambiente o
  modificabili con `ak configure`. Il dominio pubblico resta distinto dal
  percorso Docker Desktop dell'agente MSI.
- La matrice Windows ora è completa come quella deb: `aegis-server` installa
  solo Aegis, `kraken-server` solo Kraken, `aegis-suite` entrambi; l'MSI agente
  resta solo endpoint. Ogni pacchetto è autosufficiente, espone `ak.cmd` nel
  `PATH` di macchina e genera il proprio `server.env`/`kraken.env` al primo
  `ak start`. Aegis e suite chiedono FQDN/email ACME/porta; Kraken-only non ha
  un bordo TLS pubblico. Usano Docker Desktop, quindi l'avvio è al login
  (`ak start` o scheduled task), non pre-login.
- Aggiunto `ak update` su Linux e Windows: risolve l'ultima release stabile o
  una versione esplicita, verifica il checksum SHA-256, preserva FQDN/email/
  porta, aggiorna CLI e payload e riavvia i servizi. Un downgrade richiede
  `--allow-downgrade` e un backup del database verificato. Aggiunta la
  [release policy](docs/RELEASE_POLICY.md): 4.3.x corrente, 4.2.x precedente,
  <=4.1.x EOL; gli artefatti pubblicati restano immutati.
- Validazione FQDN/email più rigorosa su Linux e Windows, con rifiuto di un
  dominio pubblico senza email ACME, URL pubblico non coerente e label DNS
  non valide. La configurazione Windows resta valida anche per Kraken-only,
  che usa un env separato.
- Verificato lo stack Aegis+Kraken su Docker Desktop/Windows: Brain, Link,
  frontend, Caddy, Kraken, sensori e broker healthy, HTTP 200 su Brain,
  frontend, Kraken e Caddy. Il pacchetto Windows riusa lo stesso runtime e la
  stessa sorgente; resta la differenza di boot timing, non un componente mancante.
- La firma di default dei pacchetti server è self-signed (chiave GPG locale
  esportata come `aegis-pilot-signing-key.asc`): è accettata per il pilot, non è
  una identità pubblica e non viene mai etichettata come production. La firma
  production resta un input dell'operatore. GPG è opzionale per un pilot locale:
  `SIGNING_MODE=unsigned` è disponibile e SHA-256 resta il controllo di
  integrità.
- Il soak 7 giorni è dichiarato test interno e **rinviato al ciclo successivo**,
  dopo firewall/DNS e i miglioramenti a sensori, telemetria e processi. La 4.3.0
  non lo aspetta: il soak v4.0.0 era passato e il delta 4.3 è piccolo; il primo
  campione 4.3 non è un soak completato. Il runner non è nei pacchetti e non è
  una richiesta al cliente.
- Documentato il reset WSL2 (`wsl --shutdown`) che ha risolto il timeout
  `HCS_E_CONNECTION_TIMEOUT` del VM condiviso con Docker Desktop.

### Validazione approfondita e detection hardening (2026-11-23)

- Aggiunto `scripts/deep_simulation.py`: simulazione end-to-end contro lo stack
  MSI reale, con 39 casi malevoli, 46 benigni e i casi dual-use inviati come
  eventi veri attraverso il flusso di enroll. Ogni caso usa un agente dedicato,
  così la soppressione degli alert per agente/regola/processo non falsa il
  conteggio. Report in `docs/benchmarks/4.3/DEEP_SIMULATION.md` accanto al JSON
  grezzo; rieseguibile senza modificare il prodotto.
- Risultato dell'esecuzione registrata (738 s): TP 38, FN 1, FP 0, TN 46,
  precision 1.000, recall 0.974, F1 0.987, false positive rate 0.000, severità
  corretta 23/28, e 40/40 controlli funzionali PASS (ciclo di vita degli alert,
  RBAC viewer, isolamento, telemetria, resolver, ingest Kraken e outbox).
  L'unico FN è dichiarato: `/etc/shadow` (T1003.008) non ha una regola statica e
  richiede audit di file access che questo set di eventi non raccoglie.
- Soak 10 agenti × 120 s nella stessa esecuzione: 15.860 richieste accettate,
  0 errori, 0 eventi persi, 132.07 rps, p50/p95/p99 74.1/98.0/178.5 ms.
  Non sostituisce il soak di 7 giorni, che resta rinviato al ciclo successivo.
- Rimossi quattro falsi positivi misurati su host puliti (`vssadmin list
  shadows`, `schtasks /change`, `curl https`, `explorer → cmd`) e aggiunti 15
  test di regressione in `aegis-brain/tests/test_detection_hardening.py`.
- Le liste di processi, moduli e anomalie sono limitate a 500/256/200 elementi
  e, quando il limite scatta, la risposta porta il marker `quality`. Prima un
  payload da 600 processi veniva rifiutato con 422 e si perdeva la telemetria
  dell'intero evento; ora l'evento passa e il troncamento è dichiarato.
- Riaprire un alert azzera la soppressione del pattern, così la riapertura
  manuale non lascia la detection silenziata per una settimana.
- CI: i controlli sul contenuto dei pacchetti deb usavano `grep -q` in una
  pipeline; il grep chiude lo stream, il produttore muore con SIGPIPE e lo step
  falliva pur essendo il controllo corretto. Ora il grep legge il file e
  l'exit status è quello del controllo.
- Limite di enrollment documentato invece che corretto a ridosso del tag:
  `/enroll` accetta 10 richieste al minuto per IP sorgente ed è un controllo
  anti brute-force, non un parametro da alzare. Il runbook spiega come arruolare
  una flotta in batch; il retry dell'agente che rispetta
  `Retry-After`/`X-RateLimit-Reset` e la recovery del servizio Windows sono
  pianificati per la 4.4.

### Aegis Agent 4.3.0 — parità funzionale NodeTrace e Guard

**Stato: release 4.3.0 per pilot controllati.** Il runtime Go e il profilo
`unified` sono verificati contro il Brain reale; la release non è production GA
e non dichiara la certificazione malware. Il bundle 4.3 non contiene più Guard
Java e NodeTrace Python: restano solo nel sorgente per compatibilità 4.2.1 e non
sono offribili per nuovi deploy. Il rollback agli agenti legacy non è un
requisito della 4.3.0 ed è esplicitamente fuori perimetro.

NodeTrace (`sensor`) è stato verificato con la suite Python (82 test, 2 skip) e
con 84 funzioni di test Go su tutti i package. Il live test del binario copre
enroll, CSR, `token.json`, heartbeat, `/update`, comandi, ack, scan e header
`X-Client-Cert-Hash`; è stato eseguito sia con Brain finto sia contro il Brain
reale locale, con telemetria persistita in PostgreSQL.

Guard (`endpoint`) è stato portato per capacità, non come traduzione meccanica
dei 140 JUnit: `secret.json`/`agent_id`, enrollment `/enroll/enroll`, outbox
batch 25/500 ms con buffer 2.000, spool AES-256-GCM 50 MB con quarantena dei
file corrotti, FIM fsnotify, YARA CLI fail-closed, consumer ETW, monitor
processi con PID+start time, registry/servizi/persistenza/Defender/Authenticode
e le 14 azioni (kill, kill tree, block IP e temporaneo, quarantine, remove
persistence, DNS sinkhole, collect IOC, verify, isolate/deisolate, FIM, YARA,
update delegato). Il live test del binario copre identità, heartbeat/metriche,
comandi, ack e header `X-Client-Cert-Hash`; sul Brain reale il profilo endpoint
ha riportato FIM e response actions attivi, con ETW/YARA dichiarati non
disponibili su questo host.

Il profilo `unified` usa una sola identità Guard e un solo outbox, ma avvia
anche i collector sensor. Il Brain/UI lo accettano in enrollment, token di
deploy, job, OTA, Discovery e telemetria recente. Il bundle 4.3.0 contiene solo
l'agente Go per Windows e Linux: `unified-latest.zip`, `unified-latest.tar.gz` e
le copie versionate `unified-4.3.0.*`. L'archivio Windows include
`aegis-agent.exe` e `aegis-etw.exe`; quello Linux include `aegis-agent`,
`aegis-collector` e `aegis_exec.bpf.o`. `release-smoke.py --require-agent`
rifiuta un bundle senza questi file e rifiuta esplicitamente Guard/NodeTrace e i
binari grezzi. Il servizio/installer drop-in firmato è nella 4.3; resta fuori
il rollback Java/JRE/Python, insieme alla certificazione reale di malware e
corpus.

Evidenza eseguita il 2026-11-18 (fake) e il 2026-11-19 (stack reale):

| Gate | Risultato |
|---|---|
| `go test ./... -count=1` | 84 funzioni di test Go, tutti i package verdi |
| `go vet ./...` | verde |
| build Go Windows e Linux | verde, Go 1.27.4 |
| `mvn test` Guard Java | 140 test JUnit, 0 failure/error (Temurin 25.0.5.8) |
| NodeTrace Python | 82 test, 0 failure, 2 skip |
| live sensor/Guard con Brain finto | verdi; contratto di rete e comandi osservato |
| live sensor/endpoint/unified con Brain reale | verdi; righe telemetria 1/18/17, capabilities popolate |
| primo avvio unified con token monouso | token consumato, agent_type=unified, telemetria presente |
| deploy API unified | token 200, install.ps1/sh 200, job `manual_required`; only `oneline` accepted, no SSH/WinRM executor |
| bundle agent runtime | `unified-latest.zip` scaricato dal Brain 4.3, eseguito come `agent_type=unified`, telemetria persistita e agente revocato |
| A/B locale 2×8 s | NodeTrace 27.28 MB RSS vs Go sensor 18.43 MB; Guard Java 126.45 MB vs Go endpoint 18.77 MB |

Il benchmark è in `docs/BENCHMARK.md` e i dati grezzi in
`docs/benchmarks/4.3/agents-ab.json`. È una misura di footprint e startup su
Brain finto, non di ingestione PostgreSQL, mTLS/Caddy o flotta. Il vantaggio
misurato è la riduzione di RSS e artefatto; la CPU dell'endpoint Go è
comparabile a Java e non viene dichiarata più bassa. Durante la misura è stata
corretta una regressione reale del polling Windows (WMI/Authenticode per tutti
i processi ogni secondo), che saturava un core.

**Perimetro dichiarato:** la 4.3.0 include i percorsi packaging firmati
MSI/deb/RPM/ipk, il servizio nativo, la firma Authenticode provider-agnostica,
la modalità GPG production e la firma cosign keyless del tag. Restano fuori il
rollback Java/JRE/Python e la certificazione reale di malware/corpus, che
richiede un laboratorio autorizzato. Lo smoke contro il Brain reale è reale, ma
non è un test di flotta né di servizio installato. Il bundle non contiene più
Guard/NodeTrace, che restano solo nel sorgente per i 4.2.1 già installati.

**Evidenza di release:** clean install isolata da sorgente senza artefatti
(`aegis-clean43`) con volumi nuovi, bootstrap admin, enrollment reale,
heartbeat, evento agente, alert Sigma `T1110.001`, frontend e Link health;
`api_smoke.py` **21/21 ALL PASS**. La clean install del gate 6 è stata eseguita
sull'archivio `31962cd`; il bundle finale aggiunge il fix del download e i
default `unified`, è verificato con smoke 24/24 e con il download/run live
dell'agente Go contro un Brain 4.3. Il bundle ha 24 file: quattro archivi
`unified-*` e i tre helper kernel dentro gli archivi;
l'upgrade del database 4.2.1 ha preservato 68 agenti e 321 alert, con smoke
21/21. Il 50k Link, il restart del consumer comandi e i gate restano registrati
in `docs/RELEASE_GATE_4.3.md`. La CI hosted al tag è l'unico passo ancora
esterno al repository locale.

### Changed

- Unified agent modes: the single `agent_type=unified` agent now accepts
  `full`, `sensor` and `endpoint` capabilities through the token, installer,
  environment or `--mode`. A sensor-only unified agent does not start process
  monitoring, FIM, response actions or ETW; an endpoint-only agent does not
  start host telemetry or network scan. The agent record, binary, identity and
  enrollment remain one.
- Deployment Manager no longer offers or implies SSH/WinRM execution. The only
  rollout path is a short-lived token plus a one-liner copied to the target;
  the target must reach Aegis to download, enroll and heartbeat.
- Kraken sensors are internal by default. The honeypot is exposed only with the
  explicit `docker-compose.kraken-honeypot.yml` overlay, loopback-bound unless
  the operator sets `KRAKEN_HONEYPOT_BIND_IP=0.0.0.0`. SSH/HTTP are the default
  protocols; FTP/Telnet/SMB/RDP are opt-in.
- Docker Compose applies CPU/RAM/PID limits, `no-new-privileges` and
  capability drops to the application services; the sandbox broker now runs as
  a non-root user with the Docker socket group added explicitly.
- CI now runs on `dev`, `main`, `feat/**` and pull requests as well as tags. The
  release/publish job remains tag-only; a branch run is not Gate 5.
- Toolchain Go portata a **1.27.4** (ultima stabile, inclusi i fix di sicurezza
  del 2 novembre 2026) in `aegis-agent/go.mod`, nel piano 4.3 e nella CI, che ora
  esegue `go test`, `go vet` e build del binario su Ubuntu e Windows. La macchina
  di sviluppo è stata portata da Go 1.26.5 a 1.27.4 tramite il pacchetto ufficiale;
  `go version` e `go env GOROOT` ora puntano alla nuova installazione.

### Added

- Production validation harness: `scripts/soak_7d.py` (seven-day endurance with
  readiness, lost-event and RSS sampling), `scripts/dr_drill.sh` (encrypted DB
  plus PKI restore), `scripts/ha_failure_drill.sh` (same-host replica loss) and
  `scripts/multi_host_failure_drill.sh` (external PG/Redis failover trigger).
  They emit JSON evidence and fail closed on missing inputs; none is a
  substitute for the real run. `docs/PRODUCTION_VALIDATION.md` defines the
  operator inputs and the acceptance boundary.
- AP-126 evidence gate (`scripts/ap126_evidence.py`) and a three-node Kraken
  lab simulation (`deploy/kraken-lab/`). The lab is explicitly single-host,
  not a true multi-host or network-partition test.
- Optional Intune/GPO wrappers for the existing MSI (`deploy/mdm/`). They do not
  replace the MSI or the default one-liner: they verify the production
  signature, provision the one-shot token and provide local post-deployment
  validation. A real tenant is still required for tenant evidence.
- `scripts/install-autostart.ps1` and `docs/PERSISTENCE.md` make the reboot
  contract explicit for Docker Desktop, Linux Docker Engine, the Windows MSI,
  systemd and OpenWrt. The helper only configures the current user's Docker
  Desktop startup; it does not claim pre-login server availability.
- `scripts/persistence_check.py` verifies the checked-in reboot/crash contracts
  without changing the host. `--live-linux`, `--live-windows` and `--containers`
  are explicit opt-ins; a manually started agent is reported as not installed.
- Package builds now write a `.signing.json` sidecar with `mode=test`,
  `production` or `unsigned`. Test-signed CI artifacts cannot be mistaken for a
  release artifact, and a production release requires a `Valid` Authenticode
  signature with timestamp (MSI) or the operator GPG key (deb).
- Test di integrazione live del sensor Go con Brain finto: enrollment, CSR
  firmata da una CA di test, salvataggio identità, heartbeat/telemetria,
  comandi batch, ack, scan Discovery e verifica dell'header `X-Client-Cert-Hash`.
- Live reale dei profili `sensor`, `endpoint` e `unified` contro il Brain
  locale: `scripts/live_agent_profiles.py`; primo avvio unified con token
  monouso e install.ps1/install.sh generati e verificati sintatticamente.
- Base del profilo `endpoint` Guard: `secret.json`/`agent_id`, enrollment
  `aegis-guard`, report legacy e layer di validazione comandi; test di
  integrazione con Brain finto e test sulle funzioni pure.

### Fixed

- `scripts/setup.py` inizializza la PKI (CA + chiave manifest) dopo la
  readiness e prima dell'admin/smoke. Senza questo passo un clone pulito
  serviva l'installer one-liner con `503`, pur essendo lo stack sano.
- Persistenza: l'MSI configura il recovery del servizio `AegisAgent` (tre
  restart a 5 s, reset dopo un giorno) oltre all'avvio automatico; l'unità
  Linux usa `Restart=always` e `StartLimitIntervalSec=0`; il one-liner Windows
  verifica `AUTOMATIC` e le failure action prima di dichiarare il successo, e
  attende la chiusura di un servizio marcato per la cancellazione. I pacchetti
  deb/RPM e l'ipk falliscono l'installazione se non riescono ad abilitare il
  servizio al boot. I container Compose usano `restart: unless-stopped`, ma
  richiedono che il demone Docker sia abilitato. `docs/PERSISTENCE.md` separa
  ciò che riparte davvero da ciò che dipende dall'host o dal lab.
- Il soak `scripts/soak_7d.py` tiene sveglio Windows con
  `ES_SYSTEM_REQUIRED` e fallisce se il wall-clock ha un buco superiore a due
  intervalli di campionamento. Un portatile sospeso non produce più un falso
  "7 giorni": il report dichiara `sleep_guard`, i gap e `require_continuous`.
- Rimosso il prototipo sperimentale `scripts/self_improvement.py` e il suo
  test. La 4.3 non contiene più componenti di auto-modifica delle detection;
  AP-126/AP-127 restano gate di evidenza esterna, non auto-improvement.
- CI now derives the Docker socket GID for the non-root Kraken broker and
  validates Vault addresses before `urlopen`; the Vault SSL context still uses
  the verified constructor with an explicit lab-only opt-out. Live telemetry
  tests skip on Darwin, where the collector is unsupported, while the macOS
  build/vet gate remains. Branch run 44916543187 is green for all non-release
  jobs; the release job remains tag-only.
- I client legacy NodeTrace e Guard ora inviano solo `X-Client-Cert-Hash`,
  coerenti con il rifiuto di `X-Client-Cert` nel Brain; il test NodeTrace
  blocca il ritorno dell'header completo.
- Gli handler Guard/Go non riportano più `ok` quando quarantena, blocco
  firewall, kill o raccolta IOC non riescono: l'errore viene propagato all'ack
  come `failed`.
- Kraken SSH now advertises an Ubuntu OpenSSH banner instead of the AsyncSSH
  default. FTP passive mode advertises a reachable host and a published passive
  range, and uploads complete on the data channel instead of a fixed sleep.
- The Kraken README no longer claims four sensors, a Docker socket in the app
  or 65+ tests; it documents six sensors, the broker-only socket and 154 tests.
- HA documentation no longer reports AP-122/AP-123 as open; both are PASS in
  the 4.3 release gate. Threat-model migrations now cite `0001..0025`.
- Il download degli artefatti (`/deploy/artifacts` e
  `/deploy/bootstrap-artifacts`) restituiva un `200` con `Content-Length`
  corretto ma zero byte: `FileResponse` attraverso il `BaseHTTPMiddleware`
  di Starlette 1.10.0 perdeva il body, quindi nessun one-liner poteva
  scaricare l'agente. La risposta ora legge l'artefatto in memoria (file da
  pochi MB) e un test di regressione copre il caso.

## [4.2.1] - 2026-11-18

The `v4.2.0` tag was created but produced no GitHub Release: its release
workflow stopped in the NodeTrace Windows package because
`nodetrace-agent.spec` was ignored and absent from the tag. `v4.2.1` tracks the
spec, runs that package job on pull requests, and is the first complete 4.2
release.

### Kraken expansion and unified SOC

- Kraken outbox batches 500 deliveries, retries only rejected events, isolates
  poison events and exposes lag metrics; lab context remains `shadow` end to
  end. Brain migration `0021` and the replay script cover deception sessions.
- Six deception Sigma rules plus `multi_sensor_same_ip` correlation, and a
  unified timeline over SIEM, deception, alert, incident and telemetry sources.
- Kraken operations UI for campaigns, sensors/fleet, topologies and Lab runs;
  Brain remains read-only. SMB and RDP sensors capture NetNTLMv2/decoy access
  and negotiation banners without relaying credentials.
- ATT&CK coverage and governed suppressions: TTL is mandatory, capped at 90
  days, and hidden-alert counts remain visible.
- Real mTLS fingerprint enforcement rejects the legacy full-certificate header;
  Guard and NodeTrace send only `X-Client-Cert-Hash`. Brain runs two workers
  with Redis-backed rate limiting.
- File intelligence is an opt-in asynchronous static-analysis job: bounded
  upload, ZIP manifest, IOC extraction and a Sigma candidate with low
  confidence and explicit provenance. The sample stays in Kraken's storage and
  deletion is verified; no detonation or network execution is implemented.

### Performance and operational hardening

- Telemetry ingestion reuses the authenticated Agent, caches the Argon2 secret
  check for 60 seconds, throttles `last_seen` writes to 30 seconds, and fetches
  context/custom rules only when a rule actually fires. Device tokens also carry
  a SHA-256 proof bound to the current Argon2 hash: a restarted worker verifies
  them without the expensive KDF, while re-enrollment/revocation invalidate the
  proof automatically and the DB revocation check still runs on every request.
- The durable, unique-event path now meets the 200 rps gate on the default
  **2-worker** stack: **289.35 rps through Caddy/TLS** (1.500/1.500 `200`,
  p50 99.1 ms, p95 159.9 ms, p99 188.8 ms) and **247.76 rps direct**
  (3.000/3.000 `200`, 3.008 DB rows, p95 194.4 ms). A 20-agent cold proof
  burst reaches **341.16 rps** (p95 52.3 ms); 100 warm events reach
  **301.16 rps** (p95 91.5 ms). Legacy agents take 79.4 ms on first contact
  and 38.7 ms after the proof backfill, with no read timeouts. The earlier
  **96–111.58 rps** figure came from the non-default 8-worker setup and is
  superseded; `synchronous_commit` remains `on`.
- The Kraken sensors container now exposes a localhost-only health listener on
  port 8000. The Docker healthcheck no longer probes a honeypot port, so it
  cannot create fake attack events; the container reports `healthy`.

### Release engineering

- The NodeTrace Windows package is built and uploaded on pull requests as well
  as tags, so the release-only path is tested before an immutable tag. The
  PyInstaller spec is tracked in the repository instead of being ignored.
- The release bundle uses `env.example`, the portable name GitHub does not
  rewrite, and the installers accept either `env.example` or `.env.example`.
- The tag workflow builds the Windows NodeTrace package and includes it in the
  bundle; no manual upload is required.
- The tag workflow generates one CycloneDX SBOM per release image, records them
  in `RELEASE_MANIFEST.json`, and runs `release-smoke.py` before publishing.
- The tag workflow produces a GitHub build-provenance attestation for the
  release assets. `docs/RELEASE_SIGNING.md` records the 4.2 decision:
  checksummed, not signed; provenance is verifiable but does not authenticate
  the publisher.
- The `e2e` CI job starts an ephemeral Compose stack, seeds a deterministic
  Kraken event and runs `api_smoke.py` plus Playwright pages/session/Kraken.
- Five operational runbooks cover compromised agents, Brain, Kraken, malware
  escape and backup/restore.

## [4.1.0] - 2026-11-16

The complete Kraken vertical: transactional outbox and retry, delegated SSO,
mounted UI, read-only Aegis view and the isolated compose profile.

### Added

- Gate 0 licensing groundwork: `LICENSE` (AGPL-3.0-only), `NOTICE`,
  `TRADEMARK.md`, `SECURITY.md`, `CONTRIBUTING.md`, and the
  `THIRD_PARTY_NOTICES.md` placeholder.
- `docs/archive/PLAN_AEGIS_KRAKEN_HANDOFF.md` v2.7: the 4.1 scope is the complete
  Kraken vertical (compose, signed ingest with outbox/retry, UI, read-only
  Aegis view, end-to-end smoke test); new sensors, campaigns, Lab and unified
  timeline move to 4.2+.
- `docs/RELEASES.md`: audit of the published tags, the release checklist and
  the release-integrity gate: no user-visible capability is called integrated
  until API, UI, docs and tests ship together. The gate now names the complete
  Kraken vertical as a 4.1 requirement.
- `docs/archive/ROADMAP.md`: explicit OSINT/SentinelX and deploy/fleet
  workstreams, separate from the release hardening checklist.
- `docs/youtrack_tickets.csv` and `scripts/youtrack_import.py`: import path for
  the findings and roadmap work packages.
- `scripts/test-restore.sh` and the nightly `Backup Restore Check` workflow:
  an encrypted backup/restore round-trip creates disposable databases and
  verifies a probe row instead of trusting the restore path by inspection.
- Kraken transactional outbox (4.1.7): the signed event is queued in the same
  transaction as the attack record, then delivered by a worker with exponential
  backoff, poison handling, stale-claim recovery and `kraken_outbox_*` metrics.
  A Brain outage no longer drops the event from the Aegis side; retries are
  idempotent because the Brain deduplicates by `event_id`.
- Kraken UI and unified Aegis view (4.1.8): Kraken is served behind `/kraken/`
  with delegated SSO — a 60-second, single-use assertion signed with the
  dedicated `KRAKEN_SSO_SECRET` — and keeps its own users, database and cookie
  scope. The UI loads only local assets and no inline JavaScript, so it works
  under the `script-src 'self'` CSP and in air-gapped deployments. The Aegis
  SPA adds a read-only Kraken page with the related events, alerts and
  incidents; Kraken-specific operations stay in the Kraken UI.
- Kraken in the root compose (4.1.9): a `kraken` profile with its own Postgres,
  Redis, network and init volume. The app no longer mounts the Docker socket;
  a dedicated sandbox broker is the only service that talks to the daemon. A
  live smoke test covers the SSH attack → event → alert/incident path, plus an
  outbox drain after a Brain outage.

### Changed

- Toolchain brought to Python 3.15.2, Java 25 (Temurin 25.0.5), Spring Boot
  4.1.2 and Node 26. The Redis serializer now uses Jackson 3; the Sigma and
  correlation loaders use pure-Python `ruamel.yaml` so Python 3.15 on Windows
  does not need MSVC. YARA remains explicitly fail-soft on Python 3.15 because
  `yara-python` has no CPython 3.15 wheel yet.
- README tagline and license section now describe the actual open-source
  positioning.
- The frontend no longer loads Google Fonts: typography uses system fonts, so
  the dashboard and the Kraken UI make no external request at runtime.
- `v4.1.0` is the next release. It is a hardening minor, not a new major; the
  version fields in the code stay at `4.0.0` until the release PR.

### Security

- Removed the unused `pymongo` and `motor` drivers from the Brain
  dependencies (AEGIS-LOGIC-008).
- Bumped PyJWT to `2.15.1` for the tracked advisories (AEGIS-LOGIC-009).
- NodeTrace no longer passes device secrets in `curl` arguments; headers use a
  `0600` config file and the body goes through stdin (AEGIS-SEC-011).
- OTA updates now require an Ed25519-signed manifest; the HMAC signed with the
  enrollment key was removed (AEGIS-SEC-002). The one-liner installer writes
  the single-use enrollment token to a `0600` file instead of the persistent
  environment and injects the manifest public key.
- Re-enrollment of an existing hostname now requires a token issued for that
  host; the static enrollment key only creates new agents. Agents send a
  machine-id, of which the Brain stores only the hash (AEGIS-SEC-001).
- `REMOVE_PERSISTENCE` deletes only the matching registry value instead of the
  whole Run key; Linux reports `unsupported` instead of a false `ok`
  (AEGIS-SEC-007).
- Other findings are documented in the handoff plan; this section lists only
  changes present on `dev`. They ship only after merge.

### Fixed

- A tab left open across a frontend rebuild no longer keeps failing to load
  lazy pages until a manual refresh: `vite:preloadError` triggers one guarded
  page reload, so the tab picks up the new chunk names automatically.

### Known limitations

- The 12 Playwright e2e tests and the opt-in Kraken vertical smoke pass
  manually against the live stack, but they are not a v4.1 CI gate; the CI
  runner is planned for 4.2. The two live detection batteries are also manual
  in 4.1.
- Release assets are checksummed with `SHA256SUMS.txt` and verified against
  `RELEASE_MANIFEST.json`. Cosign signing is a separate release step: a bundle
  without `SHA256SUMS.txt.sig` is checksummed, not a signed production
  artifact.

## [4.0.0] - 2026-09-21

### Added

- Windows kernel telemetry through ETW, ingested into the same enrichment
  pipeline as the process poll (`provenance=etw`, explicit degraded quality
  when the collector is missing); Linux keeps native eBPF.
- Sigma compiler with field modifiers and fail-loud exclusions, correlation
  windows, alert policy with trusted-signed suppression and triage muting.
- Telegram as a read-only remote control (`/status`, `/alerts`, `/help`) and
  severity-filtered notifications.
- One-line signed enrollment for Guard and NodeTrace, including Windows service
  and systemd registration, Java version verification, and honest failure
  reporting.
- `scripts/pack-artifacts.py` for the artifacts served by the Brain.
- `aegis.bat services` for one-command persistent agent installation.

### Fixed

- Release packaging copied the shaded Guard jar correctly and no longer
  attached an empty release.
- SBOM generation and NVD dependency-check retries were hardened.
- Heartbeat interval is read from the database; session re-login is safe.
- Guard dependency bumps clear the tracked HTTP client advisory.

### Security

- A live enrollment key was removed from `HEAD`; history rewrite is still
  planned separately.
- Service installs read the enrollment key from the environment instead of the
  repository.

### Release assets

`aegis-guard.jar`, `sbom.spdx.json`, `SHA256SUMS.txt`. Brain, Link, Frontend,
NodeTrace, the compose bundle and upgrade notes were **not** released; this is
tracked as AEGIS-REL-002.

## [3.0.0] - 2026-07-09

### Added

- Standalone NodeTrace and Guard builds (PyInstaller, Maven + jlink).
- Discovery Center: ping sweep, ARP, TCP scan, reverse DNS, OS guess, IP
  reputation, and agent status per host.
- Remote deployment through WinRM/SSH (later replaced by signed enrollment).

### Changed

- CI moved to GitLab only in this release; GitHub Actions was restored later.

### Fixed

- `curl_http` fallback when `curl.exe` fails in a PyInstaller bundle.
- Guard command polling handles a JSON `null` without error spam.
- Database pool recycling prevents connection exhaustion.
- Dashboard WebSocket defaults to the local host instead of a broken URL.

### Tests

Release notes report 166 tests passing.

## [2.0.0] - 2026-05-29

### Changed

- The Brain became a modular monolith, consolidating heuristics, AI, OSINT and
  VaultX domains while keeping the asynchronous pipeline.
- Guard and NodeTrace became the two supported agents.
- Shared API keys were replaced by per-agent enrollment and revocable
  credentials.
- VaultX introduced AES-256-GCM envelope encryption.
- The AI suite added prompt-injection protection and Redis-backed rate limits.
- CI/CD moved to GitLab in this release.

### Added

- Extended detection that correlates endpoint processes with OSINT and
  performance anomalies.
- Zero-trust ingestion through Aegis-Link and Redis before telemetry reaches
  the Brain.

## [1.0.0] - 2026-05-15

### Added

- Initial EDR stack: Guard (Java 21), Aegis-Link (Spring Boot), Brain
  (FastAPI), and a React dashboard.
- Heuristic detection for known attack tooling, double extensions, suspicious
  execution paths, encoded PowerShell, and privilege anomalies.
- Asynchronous Redis-backed ingestion, PostgreSQL persistence, Docker Compose
  deployment, and Windows/Linux installation scripts.

[4.3.0]: https://github.com/Terminalkid09/aegis-ecosystem/compare/v4.2.1...HEAD
[4.1.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v4.1.0
[4.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v4.0.0
[3.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v3.0.0
[2.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v2.0.0
[1.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v1.0.0
