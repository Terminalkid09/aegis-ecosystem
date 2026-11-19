# Piano d'azione 4.3.0 — un solo agente Go

**Stato:** CUTOVER A — parità funzionale NodeTrace implementata e misurata nel
modulo Go (`config`, token, CSR/mTLS, telemetria Windows/Linux, scan, OTA
Ed25519, probe kernel, auditd, eBPF, evidenza Linux, comandi e PID lock).
CUTOVER B — Guard è portato per capacità: `secret.json`/`agent_id`, enrollment,
outbox/spool cifrato, FIM, YARA, ETW, monitor processi, registry/servizi/
persistenza/Defender/Authenticode e 14 azioni. Test Go, vet, build
Windows/Linux, 140 JUnit Java e live test con Brain finto sono verdi.
CUTOVER C — il profilo `unified` è implementato nello stesso binario e
verificato contro il Brain reale: una sola identità Guard, un solo outbox, più
collector sensor; Brain/UI lo accettano in enrollment, deploy, OTA e telemetria
recente. **La parità è funzionale, non ancora di produzione**: artefatto
unificato, servizio/installer drop-in, rollback Java/JRE/Python su host reale e
attivazione ETW/YARA restano gate aperti.

**Data:** 2026-11-19

**Base:** `v4.2.1`, tag annotato su `1de7443` (release pubblicata e verificata).

**Decisione collegata:** la `v4.2.2` non esiste e non verrà creata. I due debiti
di release engineering della 4.2.1 (path del checksum dell'archivio immagini e
smoke metrico flaky con due worker) entrano nella fase 0 della 4.3.0.

---

## 1. Decisione in una pagina

La 4.3.0 sostituisce **Guard (Java 25 + JNA)** e **NodeTrace (Python)** con un
solo agente Go, un solo servizio, un solo enrollment, un solo updater e un solo
contratto eventi.

Non è una release additiva come la 4.1 o la 4.2. È una sostituzione di
piattaforma endpoint con migrazione degli host già installati. Per questo il
tempo è molto maggiore: non basta riscrivere i collector, bisogna mantenere il
contratto con Brain/UI, preservare le identità, evitare il doppio agente,
sostituire i test e verificare install/upgrade/rollback su OS reali.

Decisioni di perimetro:

- `aegis-link` **resta Spring Boot**. Non è un agente e non entra nel rewrite.
  I suoi test JUnit restano: riscriverli in Go richiederebbe riscrivere il
  gateway, che è un progetto separato.
- macOS resta fuori dalla 4.x. Senza EndpointSecurity non c'è parità reale.
- OpenWrt non è un profilo endpoint. Il network sensor è un binario separato
  (`aegis-net-sensor`) nella traccia 4.5; il profilo `router` resta solo un
  placeholder di laboratorio, da non estendere e da non presentare come
  network sensor (vedi `docs/PLAN_POST_4.3.md`).
- La response intelligence resta 4.4: la 4.3 trasporta le azioni di risposta
  esistenti, non ne aggiunge di nuove.
- Kraken resta un servizio separato con DB, Redis, rete e UI propri.

Regole documentali:

- Il **README** viene aggiornato in modo fattuale: un solo agente Go, un solo
  servizio, nuovi comandi di build/test/install, niente riferimenti a Guard o
  NodeTrace come agenti correnti.
- La **motivazione del cambio** da due agenti (Python + Java/JNA) a un solo
  agente Go vive **solo nel CHANGELOG**, nella sezione `[4.3.0]`. Non va
  duplicata nel README né negli altri documenti.
- Gli altri documenti vengono aggiornati solo dove un riferimento a Guard,
  NodeTrace, JRE, NSSM o PyInstaller renderebbe l'istruzione falsa.

### 1.1 Sequenza concordata: due cutover, un solo codice

La separazione dei **cutover** è accettata. Non è accettata la separazione in
due codebase Go da unire dopo: sarebbe la fonte principale di conflitti,
duplicazione di outbox/identità/update e test da rifare.

La sequenza corretta è:

1. **Un solo modulo Go da subito**, con un solo `go.mod`, un solo albero
   `internal/` e un solo binario. I profili sono configurazione/build tag, non
   fork del repository.
2. **Cutover A — NodeTrace.** Si implementa il profilo `sensor` e si sostituisce
   solo il runtime Python. Guard Java resta intatto. L'agente si presenta come
   `agent_type=nodetrace` e riusa `token.json`/`device_id`: è un drop-in, non
   un nuovo host nel Brain. Test, benchmark e rollback Python sono il gate.
3. **Cutover B — Guard.** Si aggiunge il profilo `endpoint` allo **stesso**
   modulo. L'agente si presenta come `agent_type=aegis-guard` e riusa
   `secret.json`/`agent_id`. NodeTrace Go continua a girare. Test, benchmark e
   rollback Java/JRE sono il gate.
4. **Cutover C — unificazione.** Solo quando A e B sono verdi si passa a
   `agent_type=unified`, un solo servizio `AegisAgent`, una sola identità
   canonica per host, un solo updater e un solo installer. Qui si rimuovono i
   servizi vecchi e si chiude il rollback. Durante A e B possono coesistere
   due servizi sullo stesso host, ma sono i due ruoli separati: nessun doppio
   NodeTrace e nessun doppio Guard. Il target a un solo servizio si raggiunge
   solo in C.
5. **Brain/Link incrementali.** In A e B il server accetta l'artefatto Go sotto
   il tipo legacy, così UI e contratto restano stabili. `unified` arriva in C.
   Link resta Spring Boot e non viene riscritto: cambia solo ciò che deve
   instradare o riconoscere.
6. **Test e CI per ogni cutover.** I test Go del profilo sostituito e una CI
   minima che li esegue sono parte della fase, non un lavoro finale. La fase 5
   è consolidamento e rimozione dei test legacy, non il primo momento in cui
   si testa.
7. **Benchmark per ogni cutover.** A confronta Python/NodeTrace con Go sensor;
   B confronta Java/Guard con Go endpoint; C confronta due agenti con un solo
   agente. Senza numeri riproducibili non si dichiara il vantaggio.

Quindi "unire i 2 codici" non sarà un merge: sarà abilitare il secondo profilo
nello stesso codice e unificare tipo, servizio, identità e deploy. Questo
conserva la riduzione del rischio richiesta, senza creare due prodotti Go da
riconciliare.


### 1.2 Router, network sensor, per-server e perché la 4.3 non sposta ancora tutto

**Correzione 2026-11-19:** `router` indica una collocazione, non una capacità.
Il network sensor che vede la LAN è un **prodotto separato**
(`aegis-net-sensor`), non un quarto profilo di `aegis-agent`. Il profilo
`router` attuale è un **placeholder di laboratorio**: ricade nel ramo `sensor`,
non fa packet capture e non vede il traffico degli altri host. Non va esteso e
non va venduto come network sensor. Perimetro e fasi: `docs/PLAN_POST_4.3.md`.

Il profilo `router` è un profilo di **laboratorio OpenWrt** per un apparato di
rete: telemetria minima, nessun FIM/YARA/ETW, nessuna remediation endpoint. Non
è un profilo di produzione e non è il modo per portare “l'agente sul server”.
La distinzione corretta è per ruolo, non per nome di macchina:

- `sensor` = sensore NodeTrace su server e host Linux/Windows: telemetria,
  processi, rete, kernel/auditd, scan e OTA.
- `endpoint` = Guard su workstation o server: processi, FIM, YARA, ETW e
  risposta (isolamento, quarantine, kill, IOC), con identità Guard separata.
- `router` = laboratorio, capacità ridotte e dichiarate; non è un network
  sensor e non è il target di produzione.
- `unified` = un solo agente/identità/servizio con le capacità di entrambi. Non
è un quarto codebase: è lo stesso binario Go. Oggi è disponibile e usato nei
test locali, ma non è ancora il default di produzione finché AP-115 non chiude
artefatto, servizio e rollback.

Perché non si usa sempre `unified`:
- un host che deve solo inviare telemetria può usare `sensor`, con meno
  privilegi e senza remediation;
- un host che deve rispondere usa `endpoint` (o `unified` se deve anche
  collezionare il sensore);
- `router` è un profilo di laboratorio OpenWrt, non un endpoint e non un modo
  per installare l'agente su un server;
- la migrazione di un host già iscritto deve preservare `token.json` o
  `secret.json`, altrimenti cambia identità e crea un record duplicato;
- il cutover di produzione richiede servizio, installer, rollback e prova su
  host reale, non solo il runtime.

La 4.3 non sposta “tutto” sul router perché il router non è l'endpoint e non
può eseguire le capacità di risposta. La sequenza resta A (sensor) → B
(endpoint) → C (`unified`), con lo stesso modulo Go e binario; il “per server”
si configura con `sensor` o `endpoint` (o `unified` per entrambi), non con un
quarto agente.

Il caso “vedere tutti i dispositivi della LAN” richiede un **network sensor**
con capture/flow, DNS/DHCP e policy nftables, collocato sul gateway o su una
porta SPAN/TAP. È una traccia 4.5 separata: non è un profilo endpoint e non
entra nel pacchetto `unified`.

---

## 2. Stato reale degli agenti

### 2.1 Guard — Java 25 + JNA

| Voce | Stato attuale |
|---|---|
| Codice principale | 6.841 righe Java, 34 file |
| Test | 2.114 righe, 21 classi, **140 test JUnit** |
| Runtime | Java 25; JAR shaded + JRE minimale prodotto con `jlink` |
| Servizio Windows | NSSM, nome `AegisGuard`, directory `C:\Program Files\Aegis\Guard` |
| Servizio Linux | systemd `aegis-guard`, `/opt/aegis/guard`, `User=root` |
| Identità | `secret.json` con `agent_id`, `agent_secret`, `server_url`; PEM `device.key`/`device.crt`; CSR EC P-256 e rinnovo |
| Trasporto | `POST /telemetry/report` e `/report/batch`; Bearer + `X-Agent-Id`; `X-Client-Cert-Hash` |
| Affidabilità | outbox batch 25/500 ms, buffer 2.000, spool AES-256-GCM 50 MB, retry con jitter |
| Comandi | 14 tipi: 12 di remediation/isolation/OTA (kill, kill tree, block IP, block IP temporaneo, quarantine, remove persistence, DNS sinkhole, collect IOC, verify, isolate, deisolate, update) e 2 di scansione/FIM (FIM watch, YARA scan) |
| Windows | Toolhelp32 via JNA; ETW tramite `aegis-etw.exe`; FIM `WatchService`; registry via `reg.exe`; servizi/persistenze/Defender read-only; Authenticode via `WinVerifyTrust`; YARA via `yara64.exe`; firewall via `netsh` |
| Linux | polling `/proc`, `ss`, FIM, isolamento `iptables`, OTA; nessun collector eBPF proprio |
| macOS | `MacOSProcessMonitor` via libproc/JNA, fuori perimetro 4.x |

Punti importanti emersi dall'analisi:

- JNA è usato davvero per Win32 (`kernel32`, `wintrust`) e libproc; non è un
  dettaglio sostituibile con una riga di configurazione.
- L'ETW attuale non è JNA: è un **processo C separato** (`aegis-etw.exe`, 263
  righe) letto da stdout. Un agente Go che vuole un solo processo deve
  assorbire quel consumer, non limitarsi a copiare il polling.
- Lo spool è già un contratto utile: la migrazione deve preservare gli eventi
  non ancora consegnati, non solo il binario.
- La firma OTA è già Ed25519 e va mantenuta; l'HMAC legacy non va reintrodotto.

### 2.2 NodeTrace — Python

| Voce | Stato attuale |
|---|---|
| Codice | 3.767 righe Python incluso il test; `agent.py` 821 righe |
| Test | **82 test function** in 7 file |
| Runtime | Python 3.15 + PyInstaller, bundle `nodetrace-agent` |
| Servizio Windows | NSSM, nome `AegisNodeTrace`, `C:\Program Files\Aegis\NodeTrace` |
| Servizio Linux | systemd `aegis-nodetrace`, `/opt/aegis/nodetrace` |
| Identità | `token.json` con `token`, `device_id`, `server_url`; PEM device; CSR EC P-256 |
| Registrazione | `POST /register`, poi heartbeat `/heartbeat`, telemetria legacy `/update`, comandi `/commands` |
| Telemetria | CPU/RAM/disco/rete, processi top 25, utenti, connessioni, anomaly locali |
| Kernel | `NODETRACE_EBPF=1`: collector esterno eBPF; fallback `auditd` mirato; probe kernel |
| Evidenza Linux | systemd, cron, SSH keys (solo impronte), profili shell, moduli, capability, container, permessi file sensibili |
| Altro | network scan e report verso Discovery; OTA Ed25519; aggiornamento staged |

### 2.3 Accoppiamento con Brain e UI

La 4.3 non è solo lato agente. Oggi il server e la UI hanno punti hard-coded:

- `VALID_AGENT_TYPES` in `deploy.py` accetta solo `nodetrace` e `aegis-guard`;
- `artifact_name_for()` produce solo `nodetrace-...zip` o `aegis-guard-...zip`;
- i token di enrollment accettano `nodetrace|aegis-guard|both`;
- la pagina Deploy e Discovery espone due agenti o “both”;
- `/telemetry/recent` filtra `agent_type IN ('nodetrace','NodeTrace')`;
- il titolo “Host Telemetry — NodeTrace agents” e le etichette UI sono
  specifiche di NodeTrace;
- `discovery.py` contiene comandi locali che avviano `nodetrace-agent.exe` e
  `aegis-guard.jar`;
- `release-bundle.py`, `pack-artifacts.py`, `release-smoke.py`, `ci.yml`,
  `setup.py`, `pilot.py`, `audit_report.py` e gli installer citano i due
  agenti, il JAR, il JRE, NSSM o PyInstaller;
- il modello `Agent` identifica un host per `hostname + os_type`, non per
  coppia di agenti. La migrazione deve gestire sia due record distinti sia un
  record conteso da due enrollment. Non si può assumere che “due agenti”
  significhi sempre “due righe pulite” nel database.

### 2.4 Cosa manca oggi

- Il profilo `sensor` Go copre la parità NodeTrace descritta sopra ed è stato
  verificato con test, live su Brain finto e benchmark A/B locale. Non è un
  cutover di produzione finché mancano install/upgrade/rollback su host reale
  e la prova live di eBPF/auditd.
- Il profilo `endpoint` (Guard) copre outbox/spool, FIM, YARA CLI, ETW,
  registry/servizi/persistenza/Defender/Authenticode, monitor e le 14 azioni;
  test Go, live fake Brain, live reale e i 140 JUnit Java sono verdi. Sul live
  reale FIM e response actions erano attivi; ETW e YARA erano dichiarati non
  disponibili. Restano gate: servizio/installer drop-in, rollback Java/JRE su
  host reale e mappatura 1:1 dei test. Guard Java resta il runtime di
  riferimento fino a quei gate.
- Il profilo `unified` esiste nello stesso binario, con una sola identità Guard
  e un solo outbox; il live reale ha prodotto telemetria e capabilities. Restano
  aperti artefatto `unified-latest.zip`, servizio/installer e benchmark C.
- Il benchmark A/B locale è stato eseguito (2×8 s, Brain finto) e ha trovato
  una regressione di CPU nel polling Windows, corretta; non è una misura di
  ingestione o di flotta.
- Il tipo `unified` è accettato da enrollment, deploy, OTA, Discovery e
  telemetria recente; la UI espone token e job. Non è ancora il default di
  produzione.
- Non esiste ancora una procedura di migrazione delle identità.
- Il PID lock impedisce due processi nella stessa home, ma non c'è ancora un
  test end-to-end che impedisca la coexistenza dei due servizi legacy.
- Non esiste un artefatto singolo per Windows e Linux.
- Restano aperti i due debiti della 4.2.1 e la documentazione di release stale.

---

## 3. Matrice di parità

Ogni capacità deve finire nel nuovo agente o essere dichiarata fuori perimetro
con motivazione. La matrice è un gate, non un documento descrittivo.

| Capacità | Guard attuale | NodeTrace attuale | 4.3 `endpoint` | 4.3 `sensor` | 4.3 `router` (placeholder) |
|---|---|---|---|---|---|
| Enroll / identità / mTLS | sì | sì, formato diverso | unico | unico | unico |
| Heartbeat e capabilities | sì | sì | unico | unico | unico |
| Eventi processo | polling + ETW | eBPF/auditd | polling + ETW | eBPF/auditd | proc minimale |
| Eventi rete | netstat/ss | psutil/net_connections | nativo/fallback dichiarato | nativo/fallback | minimale |
| FIM | `WatchService` | assente | sì | configurabile | no |
| YARA | `yara64.exe` on-demand | assente | `yara64` CLI fail-closed | no | no |
| Registry / servizi / persistenza Windows | sì, read-only e comandi | assente | sì | no | no |
| Defender / Authenticode | sì | assente | sì | no | no |
| Remediation | 12 comandi | telemetry-only | sì | no | no |
| Isolamento host | netsh/iptables | assente | sì | no | no |
| eBPF Linux | assente | collector esterno | integrato | integrato | no |
| auditd Linux | assente | fallback | fallback | fallback | no |
| Evidenza Linux | assente | systemd/cron/SSH/moduli | sì | sì | minimale |
| Telemetria host | eventi | CPU/RAM/disco/processi/utenti | sì | sì | sì |
| Network scan / Discovery | assente | sì | sì | sì | no |
| OTA Ed25519 | sì | sì | unico | unico | unico |
| Servizio Windows / Linux | NSSM / systemd | NSSM / systemd | packaging da completare | packaging da completare | systemd/OpenWrt lab |
| Un solo binario agente | no | no | **sì** (helper ETW opzionale) | **sì** | **sì** |

Il profilo `router` nella matrice è solo il placeholder di laboratorio: non
significa packet capture, visibilità LAN o policy di rete. Il network sensor
è il binario separato `aegis-net-sensor` descritto in
`docs/PLAN_POST_4.3.md` (traccia 4.5).

Fuori perimetro dichiarato: macOS/EndpointSecurity, driver kernel Windows,
ETW-TI, inline prevention, Android.

---

## 4. Architettura target

### 4.1 Struttura

```text
aegis-agent/
  cmd/aegis-agent/          # main, service lifecycle, profilo
  internal/config/          # env + file, compatibilità legacy
  internal/identity/        # agent id, secret, CSR, mTLS, rotazione
  internal/event/           # schema v2, boot/seq, normalizzazione
  internal/transport/       # HTTP, auth, TLS, retry, backoff
  internal/outbox/          # buffer, batch, spool cifrato, replay
  internal/commands/        # dispatch, validazione, ack
  internal/update/          # Ed25519, SHA-256, stage, allowlist, apply
  internal/health/          # capability, degrado, metriche locali
  internal/platform/windows # Toolhelp32, ETW, registry, servizi, WMI, FIM
  internal/platform/linux   # /proc, eBPF, auditd, netlink, systemd, FIM
  internal/platform/generic # hostname, hash, path, rete comune
  packaging/windows/        # MSI WiX, service, uninstall, rollback
  packaging/linux/          # deb/rpm, systemd, uninstall, rollback
  testdata/                 # golden ETW/eBPF/eventi, fixtures
```

Un solo modulo Go, un solo binario `aegis-agent`. I profili sono configurazione
e, dove serve, build tag:

- `endpoint`: parità completa Guard + telemetria NodeTrace;
- `sensor`: telemetria e kernel, senza remediation/YARA/FIM;
- `router`: build minimale OpenWrt, senza YARA/FIM/remediation, solo lab e
  **deprecata come destinazione**. Non è il network sensor: packet capture,
  flow, nftables e packaging OpenWrt vivono in `aegis-net-sensor` (4.5).

### 4.2 Processo e servizio

- Windows: servizio nativo con `golang.org/x/sys/windows/svc`; niente NSSM.
- Linux: una unit `aegis-agent.service`; root o capability esplicite per
  eBPF/risposta. Il profilo `sensor` può girare con meno privilegi.
- Un solo processo agente. Eventuali loader o librerie native (eBPF, libyara)
  sono interne al processo; non si aggiunge un secondo servizio.
- L'ETW deve essere assorbito in Go (TDH/`x/sys/windows`) o, solo se il gate
  tecnico lo impone, linkato nello stesso binario tramite CGO. Un helper
  esterno permanente è una deroga da approvare, non il default.
- L'eBPF usa `cilium/ebpf`, oggetto CO-RE incorporato con `go:embed`; niente
  collector esterno. `auditd` resta fallback dichiarato.
- YARA usa libyara via CGO, isolata in un package con build tag; se la
  cross-compilazione non è riproducibile, si spedisce la libreria firmata
  accanto al binario, non un secondo agente. La scelta va chiusa nello spike
  della fase 1.

### 4.3 Contratto

- Canonico: `EventSchema v2`, `event_id`, `schema_version`, `boot_id`, `seq`,
  timestamp wall/monotonic, `proc_start_ns`, `provenance`, `quality`.
- Trasporto: `POST /api/v1/telemetry/report` e `/report/batch`; un solo
  outbox. La telemetria CPU/RAM usa `event_type=METRICS_REPORT` con i campi
  già previsti da `EventSchema`, non la rotta legacy `/update`.
- Comandi: `/telemetry/commands` e `/commands/batch`, con ack.
- Heartbeat: `/telemetry/heartbeat`.
- Enrollment: in A/B `/api/v1/enroll` accetta `agent_type=nodetrace` o
  `aegis-guard` con l'artefatto Go; in C accetta `unified` e restituisce un
  segreto compatibile con l'autenticazione esistente.
- Auth: Bearer + `X-Agent-Id` + fingerprint `X-Client-Cert-Hash`; niente
  `X-Client-Cert` completo.
- OTA: stesso protocollo Ed25519, allowlist URL, SHA-256, stage e apply al
  restart. Il comando deve selezionare l'artefatto per OS, non solo per tipo.
- Capabilities: una mappa unica con `profile`, `process_monitor`, `etw`,
  `ebpf`, `auditd`, `fim`, `yara`, `response_actions`, `network_scan`,
  `sensor_mode`, `quality`.

### 4.4 Compatibilità

Durante la migrazione il Brain continua ad accettare `aegis-guard` e
`nodetrace` per gli agenti vecchi. Il nuovo agente usa `unified`. Le vecchie
rotte restano finché la 4.3 non è released e la finestra di rollback è chiusa;
non vengono estese con nuove feature.

---

## 5. Migrazione, identità e rollback

Questa è la parte a rischio più alto, insieme a ETW.

### 5.1 Inventario prima di toccare un host

- leggere i servizi `AegisGuard` e `AegisNodeTrace` e i processi;
- leggere `secret.json`, `token.json`, `device.key`, `device.crt`, spool e
  `update.state`;
- verificare nel Brain se l'host ha uno o due record, se l'`agent_type` è
  coerente e se l'hostname è condiviso;
- produrre un report per host: `canonical_agent_id`, identità disponibili,
  servizi presenti, eventi non consegnati, spazio disco.

### 5.2 Strategia per cutover

La migrazione non è un big-bang. Ogni cutover tocca un solo servizio; il
servizio opposto resta installato fino al proprio turno.

1. **Cutover A — solo NodeTrace.**
   - installa il profilo `sensor` e ferma/rimuove solo `AegisNodeTrace` e
     `nodetrace-agent`; `AegisGuard` e `aegis-guard.jar` restano attivi;
   - riusa `token.json`, `device_id`, `server_url`; l'agente si presenta come
     `agent_type=nodetrace`;
   - verifica che il record NodeTrace non sia conteso; se lo è, `409` e
     intervento manuale, non creazione di un nuovo host;
   - rollback: reinstalla il bundle Python 4.2.1 e ripristina `token.json`.
2. **Cutover B — solo Guard.**
   - installa il profilo `endpoint` e ferma/rimuove solo `AegisGuard` e il
     `aegis-guard.jar`/JRE; NodeTrace Go resta attivo;
   - riusa `secret.json`, `agent_id`, `server_url`; l'agente si presenta come
     `agent_type=aegis-guard`;
   - verifica che il record Guard non sia conteso; se lo è, `409` e
     intervento manuale;
   - rollback: reinstalla JAR/JRE 4.2.1 e ripristina `secret.json`.
3. **Cutover C — unificazione.**
   - solo dopo A/B verdi: installa `unified`, ferma entrambi i servizi, unifica
     identità, updater, spool e installer;
   - host con solo Guard: riusa `secret.json` e l'`agent_id` Guard;
   - host con solo NodeTrace: riusa `token.json` e il `device_id` NodeTrace;
   - host con entrambi: preferisce Guard (ha comandi, mTLS e spool), ma solo
     dopo aver verificato che il record non sia conteso; se il Brain non può
     garantire l'unicità, richiede un token host-bound e crea un record
     `unified`, revocando i vecchi;
   - rimuove servizi/pacchetti legacy dopo la finestra di rollback.
4. **Nessun merge silenzioso.** Un record ambiguo produce `409` e un report,
   non una fusione automatica. La migrazione automatica è ammessa solo quando
   hostname, OS e identità sono univoci.
5. **Spool.** Gli eventi non consegnati del vecchio servizio vengono letti e
   reinviati dal nuovo outbox, con la chiave derivata dal device secret. Se la
   chiave non è disponibile, lo spool va in quarantena e l'evento è
   contabilizzato, mai cancellato in silenzio.
6. **Nessun doppio agente dello stesso ruolo.** Ogni profilo ha un lock
   esclusivo e un controllo di processo. In A/B i due ruoli possono coesistere;
   in C l'installer verifica che non resti né un NodeTrace né un Guard.
7. **Rollback a 4.2.1.** Backup di identità, configurazione, spool e stato
   update; stop del nuovo servizio; reinstallazione del pacchetto 4.2.1 del
   ruolo interessato; ripristino di `secret.json`/`token.json`; verifica che il
   vecchio agente torni a fare heartbeat. Rollback provato su Windows e Linux,
   non solo documentato.

### 5.3 Brain

- in A/B accettare `agent_type=nodetrace` e `agent_type=aegis-guard` con
  artefatto Go, mantenendo invariati i filtri UI esistenti;
- in C aggiungere `unified` a enrollment, deploy, discovery, OTA, UI e filtri
  di telemetria;
- aggiungere un endpoint o comando amministrativo di migrazione che preservi
  `agent_id`, `meta`, sito e capabilities, senza duplicare l'host;
- mantenere le rotte legacy per gli agenti 4.2 durante la finestra di rollback
  e rimuoverle solo dopo il cutover C;
- migrazione DB solo se necessaria; il campo `agent_type` è già una stringa,
  quindi non si introduce uno schema nuovo senza motivo.

---

## 6. Sostituzione dei test

### 6.1 Regola

I **140 test JUnit di Guard** vengono ritirati e sostituiti da test Go con
parità funzionale, non da una traduzione meccanica. Un test che verifica solo
un dettaglio JNA viene sostituito dal test della syscall Go equivalente; un
test che non ha più senso perché la capacità è stata eliminata richiede una
motivazione scritta e approvata.

I **82 test Python di NodeTrace** vengono ritirati insieme all'agente Python e
sostituiti da test Go. Non si possono eliminare i test insieme al codice senza
aver coperto il comportamento nel nuovo agente. Il conteggio Go attuale (57
nomi, molti table-driven, più i live test) non è un confronto 1:1 con gli 82
metodi Python: la copertura va verificata per comportamento, non per numero di
funzioni.

I test JUnit di **aegis-link** restano: `aegis-link` continua a essere Spring
Boot. Sostituirli con Go richiederebbe il rewrite del gateway, fuori dalla 4.3.

### 6.2 Mappatura JUnit → Go

| Test JUnit | N. | Package Go di destinazione |
|---|---:|---|
| `UpdateManagerTest` | 15 | `internal/update` |
| `MonitorTuningTest` | 9 | `internal/platform/*` (tuning) |
| `IsolationManagerTest` | 6 | `internal/commands/response` |
| `ServerPinTest` | 4 | `internal/identity/config` |
| `ManifestVerifierTest` | 5 | `internal/update` |
| `MainCommandValidationTest` | 8 | `internal/commands` |
| `HashCalculatorTest` | 2 | `internal/platform/generic/hash` |
| `AegisClientUrlTest` | 5 | `internal/transport` |
| `EventOutboxTest` | 16 | `internal/outbox` |
| `FileSpoolTest` | 6 | `internal/outbox/spool` |
| `SystemEventVersionTest` | 4 | `internal/event` |
| `DeviceIdentityTest` | 6 | `internal/identity` |
| `DeviceTlsTest` | 4 | `internal/identity/tls` |
| `AuthenticodeVerifierTest` | 6 | `internal/platform/windows/authenticode` |
| `DefenderExclusionsTest` | 4 | `internal/platform/windows/defender` |
| `ExternalEventIngesterTest` | 10 | `internal/event/ingest` |
| `RegistryReaderTest` | 5 | `internal/platform/windows/registry` |
| `WindowsServiceSnapshotTest` | 7 | `internal/platform/windows/services` |
| `EtwPipeSourceTest` | 7 | `internal/platform/windows/etw` |
| `WindowsPersistenceSnapshotTest` | 4 | `internal/platform/windows/persistence` |
| `WindowsSensorKitTest` | 7 | `internal/platform/windows` |
| **Totale** | **140** | |

La mappatura è un requisito di tracciabilità: la PR che rimuove
`aegis-guard/src/test/java` deve elencare i test Go corrispondenti. Se un test
JUnit non ha un equivalente, la PR non è completa.

### 6.3 Mappatura Python → Go

Il conteggio Python è per metodo; il conteggio Go è per funzione di test e non
include tutti i casi delle tabelle. La mappatura sotto resta il gate di
copertura.

| Test Python | N. | Package Go di destinazione |
|---|---:|---|
| `test_update.py` | 28 | `internal/update` |
| `test_agent_home.py` | 5 | `internal/config/paths` |
| `test_linux_probe.py` | 13 | `internal/platform/linux/probe` |
| `test_device_identity.py` | 8 | `internal/identity` |
| `test_linux_evidence.py` | 10 | `internal/platform/linux/evidence` |
| `test_curl_http.py` | 1 | `internal/transport` |
| `test_ebpf.py` | 17 | `internal/platform/linux/ebpf` |
| **Totale** | **82** | |

### 6.4 Nuovi test obbligatori (non presenti nei due agenti)

- install/upgrade/uninstall/rollback su Windows 11 e Server 2022/2025;
- install/upgrade/uninstall/rollback su Ubuntu 22.04/24.04 e RHEL 9;
- migrazione da Guard-only, NodeTrace-only e doppio agente;
- nessun doppio servizio e nessun evento duplicato durante la migrazione;
- un solo enrollment, un solo updater, un solo spool;
- `unified` visibile in Brain e UI, telemetria recente inclusa;
- OTA per OS corretto, manifest Ed25519 e anti-rollback;
- profilo `sensor` senza remediation e capabilities `telemetry-only` visibili;
- network sensor separato avviabile su gateway Linux e, solo dopo N0, su un
  target OpenWrt dichiarato (traccia 4.5, non gate 4.3);
- soak test di 7 giorni con memory leak check e restart;
- build Go riproducibile, SBOM e scansione dipendenze.

---

## 7. Benchmark: la prova del cambio

La scelta “due agenti → uno” non si sostiene con una preferenza. Ogni cutover
produce un confronto tra vecchio e nuovo sullo stesso host, stesso carico e
stessa configurazione.

### 7.1 Confronti

| ID | Baseline | Candidato | Momento |
|---|---|---|---|
| A | NodeTrace Python/PyInstaller | Go `sensor` | fine fase 2 |
| B | Guard Java 25 + JRE + NSSM | Go `endpoint` | fine fase 3 |
| C | due agenti (Python + Java) | Go `unified` | fine fase 4 |

### 7.2 Metriche

| Area | Misure |
|---|---|
| Footprint | RSS idle, RSS dopo 24 h, picco, CPU idle e sotto carico |
| Avvio/install | tempo di enroll/startup, install, upgrade, spazio su disco, dimensione artefatto |
| Throughput | eventi/s, p50/p95 end-to-end, batch, backpressure, drop |
| Kernel | overhead eBPF/ETW (300 exec), eventi persi, CPU |
| Affidabilità | memoria dopo 24 h/7 giorni, restart, spool, reconnect |
| Operations | numero servizi/processi, dipendenze runtime, tempo di rollback |

### 7.3 Metodo

- stesso host fisico o VM, stesso kernel/OS, stesso carico e stessa policy;
- 3 esecuzioni, mediana e p95, non un singolo run;
- registrare commit, toolchain, flag di build, hardware, versioni Python/Java;
- baseline rifatta su `v4.2.1`, non numeri vecchi;
- carichi: idle 10 min, 300 exec, 1.000 eventi, 24 h soak; 7 giorni solo per
  il gate di release;
- eBPF e auditd misurati separatamente; ETW e polling misurati separatamente;
- risultati raw JSON in `docs/benchmarks/4.3/`, sintesi in
  `docs/BENCHMARK.md`; ogni numero deve avere il comando che lo riproduce.

### 7.4 Regola di decisione

- La parità funzionale viene prima: un risparmio di RAM non compensa un evento
  perso o un comando non eseguito.
- Una regressione superiore al 5% su CPU/RSS/p95 del percorso core va spiegata
  o corretta; non si nasconde nel totale.
- Se Go non mostra un vantaggio, il CHANGELOG lo dichiara. La motivazione
  architetturale si basa sui dati A/B/C, non su un confronto tra numeri vecchi.
- Il README resta fattuale; la narrativa della scelta resta nel CHANGELOG.

---

## 8. Fasi di implementazione

### Fase 0 — Baseline, debito 4.2.1, contratto di parità

**Obiettivo:** partire da una base pulita e chiudere i due difetti che
avrebbero richiesto una 4.2.2.

- [ ] verificare che la base sia `v4.2.1`/`1de7443`, non il branch locale
      `release/4.2.1` fermo a `ed6f732`;
- [ ] correggere il path del checksum dell'archivio immagini e verificare
      `sha256sum -c` dentro la directory del bundle;
- [ ] rendere deterministico lo smoke metrico con due worker: metrica statica
      sempre esposta e check che non dipenda dal worker che ha servito la
      richiesta;
- [ ] aggiornare `docs/RELEASES.md` stale;
- [ ] scrivere la matrice di parità definitiva e l'ADR dell'agente unico;
- [ ] definire i budget di RAM, CPU, dimensione binario, tempo di install e
      tempo di upgrade;
- [ ] decidere con uno spike: ETW in Go puro vs CGO, YARA CGO vs libreria
      firmata, eBPF con `cilium/ebpf`;
- [ ] inventariare identità e record Brain sui lab.

**Uscita:** nessuna 4.2.2; i debiti sono chiusi in 4.3; ETW/YARA/eBPF hanno
una decisione tecnica scritta e un test di fattibilità.

### Fase 1 — Scheletro Go e contratti condivisi

**Obiettivo:** un agente fittizio con profilo `sensor` può fare enrollment,
heartbeat, eventi, comandi e OTA stage senza collector. Guard non viene
toccato.

- [x] creare modulo, toolchain Go 1.27.4, layout, build Windows/Linux;
- [ ] config con precedenza flag > env > file e compatibilità `AEGIS_*` /
      `NODETRACE_*`;
- [ ] identità: lettura legacy, CSR, mTLS, fingerprint, rotazione;
- [ ] event schema v2 + marshal/unmarshal + golden;
- [ ] transport HTTP, auth, retry, backoff, TLS;
- [ ] outbox bounded, batch, spool cifrato, replay, contatori;
- [ ] command router e ack;
- [ ] OTA Ed25519, SHA, allowlist, stage;
- [ ] servizio Windows/Linux e lock di singola istanza;
- [ ] contratto Brain legacy `nodetrace` (poi `aegis-guard`), artifact naming
      per OS, feature flag; `unified` solo in fase 4;
- [ ] test unitari Go per tutti i package condivisi.

**Uscita:** un agente di test invia eventi e metriche a un Brain reale sotto
`agent_type=nodetrace`, riceve un comando, stages un update e non richiede
Python. NodeTrace Python resta la baseline di rollback.

### Fase 2 — Cutover NodeTrace: profilo `sensor`

**Obiettivo:** sostituire il solo NodeTrace con il profilo `sensor` dello
stesso modulo Go; Guard Java resta installato e invariato.

- [ ] parità NodeTrace su Linux: telemetria CPU/RAM/disco/processi/utenti,
      connessioni, anomaly, network scan, evidenza systemd/cron/SSH/moduli,
      capability/container, OTA e comandi;
- [ ] `/proc` per processi, uid, start time, cmdline, rete;
- [ ] eBPF CO-RE con `cilium/ebpf`, oggetto embedded, ringbuf, restart;
- [ ] auditd fallback mirato;
- [ ] parità NodeTrace su Windows: telemetria host, processi, rete, utenti,
      update e comandi;
- [ ] identità `token.json`/`device_id`, rotte `/register`, `/heartbeat`,
      `/update`, `/commands` e servizio `AegisNodeTrace` in modalità drop-in;
- [ ] `agent_type=nodetrace` durante il cutover: stesso record e stesso token,
      nessun nuovo host nel Brain;
- [ ] Brain/Link accettano l'artefatto Go sotto `nodetrace`; UI invariata;
- [ ] 82 test Python mappati in Go e test di integrazione Brain/UI;
- [ ] CI minima `agent_sensor` (Linux e Windows) verde;
- [ ] installer/bundle NodeTrace sostituito dal binario Go, mantenendo la
      possibilità di reinstallare il bundle Python 4.2.1;
- [ ] benchmark A: Python/PyInstaller vs Go `sensor`, stesso host e carico;
- [ ] canary Linux, poi Windows; rollback Python provato.

**Uscita:** un host NodeTrace gira su Go, conserva `device_id`/token, invia gli
stessi eventi e riceve gli stessi comandi; benchmark A registrato; rollback
Python verde; Guard non è stato modificato.

### Fase 3 — Cutover Guard: profilo `endpoint`

**Obiettivo:** aggiungere al medesimo modulo il profilo `endpoint` e sostituire
Guard, mentre NodeTrace Go è già in produzione.

- [x] base endpoint: `secret.json`/`agent_id`, `agent_type=aegis-guard`,
      enrollment `/enroll/enroll`, report `/telemetry/report`, comandi
      `/telemetry/commands[/batch]`, validazione IP/dominio/registry/isolation;
- [x] test di integrazione della base con Brain finto e test Go delle funzioni
      pure; `go test`, `go vet` e build Windows/Linux verdi;
- [x] test live del profilo `endpoint` con il binario reale, solo `secret.json`,
      report heartbeat/metriche, comandi e ack; pin del server normalizzato sul
      base API;
- [ ] Toolhelp32 con `x/sys/windows`, PID reuse, start time;
- [ ] ETW in Go (Kernel-Process/Kernel-Network), golden e test su Windows;
- [ ] FIM con `ReadDirectoryChangesW`/`fsnotify`, baseline e dedup;
- [ ] registry, servizi, persistenza, Defender, Authenticode;
- [ ] YARA integrata, con isolamento CGO e test;
- [ ] remediation 12 comandi, `FIM_SET_WATCH`, `YARA_SCAN`, ack;
- [ ] isolamento firewall e allowlist Brain;
- [ ] rete, hash, command line, firma/publisher, euristiche;
- [ ] parità Linux del profilo endpoint: FIM, isolamento, remediation, update;
- [ ] identità `secret.json`/`agent_id`, servizio `AegisGuard` in drop-in;
- [ ] `agent_type=aegis-guard` durante il cutover; stesso record;
- [ ] Brain/Link accettano l'artefatto Go sotto `aegis-guard`;
- [ ] 140 JUnit mappati in Go e test di integrazione;
- [ ] CI minima `agent_endpoint` (Windows e Linux) verde;
- [ ] MSI Windows e pacchetto Linux, senza JRE e NSSM; rollback 4.2.1;
- [ ] benchmark B: Java 25/JRE vs Go `endpoint`;
- [ ] canary Windows, poi Linux.

**Uscita:** Guard è sostituito dallo stesso modulo Go, conserva `agent_id`,
parità di capacità e benchmark B; rollback Java/JRE verde; NodeTrace Go resta
verde.

### Fase 4 — Unificazione finale e identità

**Obiettivo:** passare dai due cutover compatibili a un solo agente `unified`
per host. Non è un merge di codebase: il modulo è già uno.

- [x] `agent_type=unified`, una sola identità Guard, un solo outbox, più
      collector sensor; live reale `sensor`/`endpoint`/`unified` verde;
- [ ] servizio `AegisAgent`, un solo updater e un solo installer drop-in;
- [ ] installer rileva e ferma `AegisGuard` e `AegisNodeTrace`; nessun doppio
      servizio e lock di singola istanza;
- [ ] scelta identità canonica: Guard-only, NodeTrace-only, both; 409 esplicito
      per record contesi; backup di identità/config/spool/update state;
- [ ] import eventi non consegnati e verifica zero perdite/duplicati;
- [x] Brain/UI: `unified` in enrollment, deploy, OTA, discovery e filtri;
- [ ] artefatto `unified-latest.zip` pubblicato e one-liner provato su host
      target; oggi il token/script è verificato ma l'artefatto manca;
- [ ] rimozione dei servizi/pacchetti legacy dopo la finestra di rollback;
- [x] test live sensor, endpoint e unified su host locale; primo avvio unified
      con token monouso consumato;
- [ ] test Guard-only, NodeTrace-only, both, host revocato, token scaduto,
      hostname duplicato, rollback a 4.2.1;
- [ ] benchmark C: due agenti vs un solo `unified`;
- [ ] link: confermare che il gateway non richiede rewrite; test JUnit restano.

**Uscita:** un solo agente per host, identità canonica preservata, vecchi
servizi rimossi, benchmark C e rollback verde.

### Fase 5 — Consolidamento dei test

**Obiettivo:** chiudere la tracciabilità e rimuovere i test legacy. I test Go
dei due profili sono già stati scritti e resi verdi nelle fasi 2 e 3.

- [ ] verificare 82/82 test Python mappati e verdi in Go (fase 2);
- [ ] verificare 140/140 test JUnit mappati e verdi in Go (fase 3);
- [ ] aggiungere i test nuovi §6.4 non ancora coperti;
- [ ] rimuovere `NodeTrace/agents/python/tests` e
      `aegis-guard/src/test` solo dopo il verde e la tracciabilità;
- [ ] mantenere i test JUnit di `aegis-link`;
- [ ] `go test ./...`, `-race` su Linux, `go vet`, build Windows/Linux;
- [ ] test di integrazione con Brain e UI, inclusi i percorsi legacy durante
      la finestra di rollback.

**Uscita:** copertura tracciata 82/82 + 140/140, nessuna perdita silenziosa,
nessun test legacy usato come copertura unica.

### Fase 6 — Consolidamento Brain, UI, tooling e documentazione

**Obiettivo:** rimuovere i rami legacy e rendere il prodotto un solo agente.
Le modifiche Brain/Link sono state introdotte incrementalmente nelle fasi 2–4;
qui si consolidano, si testano e si documentano.

- [ ] verificare `unified` in enrollment, deploy, OTA, discovery e UI dopo la
      fase 4;
- [ ] una sola opzione di deploy al posto di Guard/NodeTrace/both;
- [ ] filtro telemetria e titoli dashboard;
- [ ] rimuovere `nodetrace`/`aegis-guard` da `VALID_AGENT_TYPES`,
      `artifact_name_for`, `build_update_command`, `pack-artifacts.py`,
      `release-bundle.py`, `release-smoke.py` solo dopo la finestra di rollback;
- [ ] rimuovere build immagini `aegis-guard`/`aegis-nodetrace` non usate dal
      compose; aggiornare SBOM e Trivy;
- [ ] aggiornare `setup.py`, `aegis.bat`, `pilot.py`, `audit_report.py`,
      `dev_preflight.py`, `test-installers.ps1`,
      `install-agents-autostart.ps1`;
- [ ] `aegis-link`: aggiornare solo routing/health/telemetry che citano i due
      agenti; nessun rewrite, test JUnit invariati;
- [ ] README fattuale: architettura, componenti, install, dev mode, build,
      auth, config, struttura, CI;
- [ ] CHANGELOG `[4.3.0]`: **unica** motivazione del passaggio da due agenti
      (Python + Java/JNA) a un solo agente Go, con riferimento ai risultati
      benchmark, non a numeri inventati;
- [ ] `docs/BENCHMARK.md`: risultati A/B/C, metodo e limiti; il README resta
      descrittivo;
- [ ] aggiornare `UPGRADING.md`, `OS_COMPATIBILITY.md`, `OPERATIONS.md`,
      `PILOT_RUNBOOK.md`, `THREAT_MODEL.md`, `RISK_MATRIX.md`, `RELEASES.md`,
      `ROADMAP.md`, `PLAN_V4.2.md`;
- [ ] rimuovere o redirigere la documentazione NodeTrace/Guard obsoleta.

**Uscita:** nessun utente vede due agenti o un runtime Java/Python per
l'endpoint; la motivazione è nel solo CHANGELOG, i dati in `BENCHMARK.md`.

### Fase 7 — Validazione e release

**Obiettivo:** `v4.3.0` costruita dal tag e verificata da download pulito.

- [ ] test unitari, integrazione, race, vet;
- [ ] Windows 11/Server 2022/2025, Ubuntu 22.04/24.04, RHEL 9;
- [ ] install, enroll, revoca, re-enroll, upgrade, uninstall, rollback;
- [ ] migrazione da 4.2.1 e rollback a 4.2.1;
- [ ] Link 50k live cap e Brain restart dopo claim senza ack;
- [ ] release bundle da download pulito e clean install guidata;
- [ ] soak 7 giorni;
- [ ] benchmark A/B/C e load 200 rps; confronto due agenti vs `unified`;
- [ ] E2E Compose e API smoke;
- [ ] SBOM, Trivy, pip-audit, `go version -m`, provenance;
- [ ] code signing Windows e pacchetti Linux: se il certificato non è
      disponibile, la release resta dichiarata non firmata, non “firmata”;
- [ ] `SHA256SUMS.txt` verificato dentro il bundle;
- [ ] tag annotato e release GitHub;
- [ ] nessun rewrite di tag, nessun force-push.

**Uscita:** release reale, non un artefatto parziale.

---

## 9. Stima

La stima è per **un solo sviluppatore** e include test, migrazione, docs e
release. Non è una data promessa.

| Fase | Sforzo indicativo | Note |
|---|---:|---|
| 0 — baseline e debiti | 1–2 settimane | include spike ETW/YARA/eBPF |
| 1 — scheletro e contratti | 3–4 settimane | dipende dal Brain |
| 2 — NodeTrace/sensor | 6–8 settimane | eBPF, auditd, evidenza; Guard intatto |
| 3 — Guard/endpoint | 8–10 settimane | ETW e YARA sono il critical path |
| 4 — unificazione/identità | 4–6 settimane | servizio unico, identità, rollback |
| 5 — consolidamento test | 3–4 settimane | test già verdi nelle fasi 2–3 |
| 6 — Brain/UI/docs | 2–3 settimane | consolidamento, non primo adeguamento |
| 7 — validazione/release | 4–5 settimane | soak incluso, non tutto effort |
| **Totale** | **31–42 settimane-persona (30 h)** | circa **930–1.260 ore** |

La fase 2 è il primo cutover e non tocca Guard; la fase 3 è il critical path
tecnico (ETW/YARA), ma non blocca il rilascio del sensore. La fase 4 non è un
merge di codice: è l'unificazione di tipo, servizio, identità e deploy.

Calendario realistico:

- **30 h/settimana:** 7–9 mesi; beta interna dopo 4–5 mesi; soak finale 7
  giorni.
- **40 h/settimana:** 5–7 mesi; beta interna dopo 3–4 mesi.
- **Due persone** che dividono Windows e Linux: 4–5 mesi, ma migrazione,
  consolidamento test e soak restano in serie.

La tabella è in settimane-persona equivalenti a 30 h; a 40 h/settimana le
stesse ore coprono 23–32 settimane. La sola riscrittura dei collector non
basta: la stima include la sostituzione dei test, la migrazione delle identità,
l'adeguamento Brain/UI, la pipeline di release e il soak.

---

## 10. Rischi e gate

| Rischio | Gravità | Mitigazione / gate |
|---|---|---|
| Due codebase Go da unire | alta | un solo modulo e profili da fase 1; nessun fork, nessun merge |
| Test/CI rinviati a fine progetto | alta | test Go e CI minima in ogni cutover; fase 5 solo consolidamento |
| Benchmark non comparabili | media | stesso host/carico, 3 run, raw JSON, baseline 4.2.1 |
| ETW in Go non raggiunge la parità TDH | alta | spike in fase 0; se serve CGO, link nello stesso binario; nessun helper permanente senza approvazione |
| YARA CGO non è cross-buildabile | alta | spike libyara; libreria firmata accanto al binario se necessario; SBOM e test |
| eBPF CO-RE su kernel diversi | alta | matrice kernel, BTF/capability probe, fallback auditd dichiarato |
| Identità duplicata o record conteso | alta | inventario, 409 esplicito, nessun merge silenzioso, backup/rollback |
| Doppio agente durante la migrazione | alta | stop + disable + lock + verifica processo, test dedicato |
| Brain/UI dimenticano `unified` | media | test API/UI e filtro telemetria; checklist hard-coded |
| Test Java/Python rimossi troppo presto | alta | mapping 140/82, PR di cutover solo a verde Go |
| Aggiornamento Windows del binario lockato | media | stage + apply al restart con lo stesso binario in modalità updater |
| Certificato Authenticode assente | media | release dichiarata non firmata; non usare “signed” |
| Scope creep verso la 4.4 | media | la 4.3 trasporta solo le azioni esistenti; nuove azioni rinviate |
| Lab Windows/Linux non disponibile | alta | la release resta bloccata finché i test reali non sono eseguiti |

Gate di approvazione:

- **G0:** matrice di parità + spike ETW/YARA/eBPF approvati.
- **G1:** scheletro Go e contratto `sensor`/`nodetrace` verdi contro Brain
  reale.
- **G2:** NodeTrace Go: parità, cutover, benchmark A e rollback Python verdi.
- **G3:** Guard Go: parità, cutover, benchmark B e rollback Java/JRE verdi.
- **G4:** `unified`: identità, migrazione, benchmark C e rollback 4.2.1 verdi.
- **G5:** test 82/82 + 140/140 tracciabili; nessun test legacy come copertura
  unica.
- **G6:** docs, release e download pulito verdi.

---

## 11. Cosa serve approvare

1. La 4.2.2 è annullata: i due fix entrano nella 4.3.0.
2. `aegis-link` resta Spring Boot e i suoi test JUnit restano.
3. I 140 test JUnit di Guard e gli 82 test Python di NodeTrace vengono
   sostituiti da test Go; nessuna rimozione senza copertura equivalente.
4. Il nuovo agente è un solo processo/servizio; eventuali librerie native
   (ETW, YARA, eBPF) non sono agenti separati.
5. La motivazione del cambio va **solo** nel CHANGELOG `[4.3.0]`; il README
   riceve solo aggiornamenti fattuali.
6. Il perimetro 4.3 resta endpoint Windows/Linux; macOS fuori. OpenWrt non è
   un profilo endpoint: il network sensor è un binario separato nella traccia
   4.5; il profilo `router` è solo un placeholder di lab.
7. La stima 7–9 mesi a 30 h/settimana è accettata come pianificazione, non
   come impegno contrattuale.
8. **Sequenza:** cutover NodeTrace → cutover Guard → `unified`; un solo
   modulo Go, non due codebase da unire. Test/CI e benchmark sono gate di ogni
   cutover, non lavoro finale.

La sequenza è approvata: il lavoro parte da `main` aggiornato a `v4.2.1`, non
dal branch locale `release/4.2.1`. Il primo deliverable è lo scheletro Go con
profilo `sensor` e contratto `nodetrace`; Guard Java non viene toccato.
