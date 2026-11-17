# Piano d'azione 4.2+

Data: 2026-11-17. Base rilasciata: `v4.1.0`, tag annotato `17c499f`.

Questo documento è l'ordine di esecuzione della prossima fase. Il perimetro
funzionale della 4.2 resta quello già deciso in
[`PLAN_AEGIS_KRAKEN_HANDOFF.md`](PLAN_AEGIS_KRAKEN_HANDOFF.md) §4.2.0; qui si
stabilisce cosa fare prima, cosa non può slittare e come si misura il
risultato. Non è un nuovo scope e non anticipa Kafka, Kubernetes o
multi-tenancy.

## Decisione corrente — agente unico Go

Data: 2026-11-17.

Guard e NodeTrace confluiscono in un solo agente Go nella **4.3.0**. La
response intelligence slitta alla **4.4.0**. `aegis-link` resta Spring Boot:
è un gateway server-side per ambienti ad alto traffico, non un endpoint, e
riscriverlo in Go non ridurrebbe il costo operativo del prodotto.

Questa decisione **non cambia la 4.2.0**. La 4.2 è quasi tutta lato
server/Kraken (canale outbox, timeline, detection, UI, flotta, SMB/RDP, mTLS);
non sta aggiungendo nuove capacità a Guard o NodeTrace. Quindi non c'è quasi
nulla da convertire due volte. Durante la 4.2 i due agenti ricevono solo fix di
sicurezza, compatibilità, CI e release; nessuna nuova feature endpoint.

Perché non alla fine della roadmap: rimandare l'unificazione dopo la response
significherebbe costruire il contenimento su due agenti che poi verranno
riscritti. La 4.3.0 è il punto più precoce in cui il rewrite può partire senza
fermare la release già pianificata.

La specifica di dettaglio 4.1/4.2 resta nell'handoff. Per la 4.3/4.4 vale
questo documento; le sezioni 4.3.x dell'handoff descrivono la response storica
e vanno lette come 4.4.x.

## Regole

1. Kraken resta un microservizio separato: DB, Redis, rete, credenziali e UI
   propri. Il Brain non esegue codice non fidato e non riceve il Docker socket.
2. Una PR per finding o per piccola verticale, con test di regressione.
3. Nessuna feature nuova prima di aver chiuso i debiti di release della fase 0.
4. Le misure si rifanno sul commit candidato; non si citano numeri vecchi.
5. Ogni release si costruisce dal tag e si verifica da un download pulito.
6. Durante la 4.2 non si aggiungono capacità a Guard/NodeTrace: solo fix di
   sicurezza, compatibilità, CI e release. Le nuove capacità endpoint vanno
   direttamente nell'agente unico 4.3.

## Fase 0 — debito di release (prima di 4.2)

Questa fase non aggiunge capacità al prodotto, ma elimina i tre punti in cui
la 4.1 ha richiesto un intervento manuale dopo il tag.

- [ ] **Nome asset portabile:** il bundle deve produrre `env.example`, non
      `.env.example`, perché GitHub normalizza i nomi che iniziano con un punto.
      Aggiungere un test che verifichi il nome finale degli asset e aggiornare
      `release-smoke.py` di conseguenza.
- [ ] **NodeTrace nel job di release:** job Windows che costruisce il pacchetto
      PyInstaller e lo carica come artifact; il job `release` lo scarica e lo
      include nel bundle. Niente più upload manuale.
- [ ] **Firma e provenienza:** cosign keyless con OIDC (`id-token: write`) per
      `SHA256SUMS.txt`, oppure una decisione scritta che dichiari la release
      non firmata. Aggiungere anche la provenienza del build.
- [ ] **SBOM per artifact:** oltre al CycloneDX del repository, generare gli
      SBOM delle immagini rilasciate e collegarli agli asset.
- [ ] **Smoke nel tag:** eseguire `release-smoke.py` e `sha256sum -c` nel job
      di release, non solo in locale.
- [ ] **E2E nel gate:** portare Playwright pagine + verticale Kraken e
      `scripts/api_smoke.py` su un runner con Docker; oggi sono gate manuali.
- [ ] **Runbook:** chiudere i cinque runbook operativi (agente compromesso,
      Brain compromesso, Kraken compromesso, malware fuori sandbox, backup).

**Uscita:** un tag di patch successivo viene pubblicato interamente dalla CI,
senza rinominare o aggiungere asset a mano.

## Fase 1 — 4.2.0: Kraken expansion & Unified SOC

Ordine per dipendenza, non per preferenza. Il dettaglio e i test di
accettazione sono nell'handoff §4.2.0.

1. **4.2.1 — canale Kraken→Aegis e replay.** Batch da 500, metriche outbox,
   replay di eventi velenosi, allineamento `deception_sessions`. Accettazione:
   1.000 eventi, zero duplicati al retry; HMAC errato 401; evento oltre la
   finestra 422; Brain spento e outbox svuotata al ritorno; `context=lab`
   distinto da `sensor`.
2. **4.2.3 — timeline unificata.** Endpoint e UI con cinque sorgenti,
   virtualizzazione, p95 < 400 ms su 10k eventi.
3. **4.2.2 — detection deception.** Sei regole Sigma con `logsource: kraken` e
   correlazione `multi_sensor_same_ip`; ogni regola ha un positivo e un
   negativo, nessun alert per scanner “solo banner”.
4. **4.2.4 — UI Kraken estesa.** Campagne, sensori/nodi, topologie e run Lab,
   sample e filtri; la SPA Aegis resta in sola lettura e non duplica la
   gestione operativa.
5. **4.2.7 — flotta sensori.** Nodi, chiavi per nodo, config firmata,
   heartbeat, desired/applied e revoca immediata.
6. **4.2.8 — sensori SMB/RDP.** Cattura NetNTLMv2 e file esca, tentativi e
   banner RDP, health e metriche; nessun relay.
7. **4.2.9 — mTLS reale e multi-worker.** Header `X-Client-Cert` diretto
   rifiutato; due worker senza duplicati; p95 < 300 ms a 200 rps.
8. **4.2.5 / 4.2.6 — ATT&CK e soppressioni governate.** Possono slittare se
   il resto è pronto, ma non possono essere presentati come completati.

**Definition of done 4.2.0**

- La verticale 4.1 resta verde: attacco SSH → UI Kraken → evento
  `siem_events` → alert/incidente → vista Aegis entro 10 s.
- UI Kraken estesa e SSO delegato funzionante senza doppia autenticazione.
- Lab shadow produce evidenze correlate, senza azioni distruttive.
- Sei regole con replay e load test 200 rps / 2 worker documentato.
- Tag `v4.2.0` costruito dalla CI e verificato dal download.

## Fase 2 — 4.2.x: file intelligence

Solo dopo la 4.2.0, e con stima rifatta. È la capacità che differenzia
davvero Aegis da un EDR/SIEM generico:

- analisi file/ZIP come job asincrono nella sandbox Kraken, con timeout,
  limiti di dimensione e kill switch;
- object storage minimo (MinIO in locale, S3 in cloud) per i campioni, con
  retention, immutabilità e cancellazione verificata;
- estrazione IoC e generazione di candidati Sigma, con provenance e
  confidence;
- process tree e DNS history nella dashboard;
- KRAKEN-SEC-003, KRAKEN-SEC-005 e i finding di release ancora aperti.

**Uscita:** un sample caricato produce un report asincrono, un IoC esportabile
e una regola candidata; la cancellazione del sample è verificata da un test e
l’oggetto non è più recuperabile.

## Fase 3 — 4.3.0: agente unico Go

**Tema:** un solo agente endpoint al posto di Guard (Java) e NodeTrace
(Python), con un solo enrollment, un solo updater, un solo contratto eventi e
un solo servizio da installare.

Il codice attuale è circa 6.800 righe Java in Guard e 3.800 righe Python in
NodeTrace, più test, installer Windows/Linux, servizio NSSM/systemd, ETW,
FIM, YARA, eBPF/auditd, OTA e identità device. Non è un “port” meccanico: è un
rewrite con parità funzionale e migrazione degli host già installati.

**Perimetro 4.3.0**

- un repository e un binario `aegis-agent`, con profili di build:
  - `endpoint`: parità Guard (processi, FIM, registry/ETW su Windows, YARA,
    remediation, OTA) più la telemetria NodeTrace;
  - `sensor`: telemetria leggera NodeTrace per host dove la remediation non
    serve;
  - `router`: build OpenWrt per il lab, senza YARA/FIM/remediation e senza
    pretesa di supporto produzione;
- Windows: servizio, ETW, registry, code signing, MSI/installer e rollback;
- Linux: eBPF/auditd, processi, file, rete, systemd e rollback;
- macOS resta fuori dalla 4.x: senza EndpointSecurity non è parità, è una
  promessa non mantenibile;
- `aegis-link` resta Spring Boot e non entra nel rewrite.

**Migrazione**

- rilevare `AegisGuard` e `AegisNodeTrace`, preservare l'identità/device secret
  e installare un solo servizio;
- evitare che vecchio e nuovo agente girino insieme sullo stesso `agent_id`;
- supportare il rollback ai pacchetti 4.2 per una minor release;
- provare upgrade da 4.2 a 4.3 su Windows 11/Server e Ubuntu 22.04/24.04
  puliti, non solo su una macchina di sviluppo.

**Accettazione**

- matrice di parità completa: ogni capacità di Guard e NodeTrace o è nel nuovo
  agente, o è dichiarata fuori perimetro con motivazione;
- nessun evento duplicato durante la migrazione;
- installazione, upgrade, disinstallazione e rollback provati su OS reali;
- OTA Ed25519 e riavvio del servizio provati;
- ETW, FIM, YARA e remediation Windows coperti da test;
- eBPF/auditd e telemetria Linux coperti da test;
- budget di RAM, CPU e dimensione del binario misurato contro i due agenti
  attuali e approvato prima del rewrite, non dopo;
- soak test di almeno 7 giorni su un host di lab;
- profilo router costruito e avviato su OpenWrt di lab, dichiarato non
  supportato in produzione.

**Stima:** la stima precedente della 4.3 (48 giornate) non copre questo rewrite. La stima va
rifatta prima di aprire la release; non è una feature da due settimane e non
si promette una data.

## Fase 4 — 4.4.0: response intelligence

Solo dopo la parità dell'agente unico. Le capacità restano quelle già decise:

- policy DNS e firewall con TTL, dry-run, approvazione e rollback;
- playbook nominati con approvazione a due livelli per azioni distruttive;
- rimozione definitiva dell’azione `script` e verifica del risultato sul host;
- canary token, dollhouse e blocco IP con audit;
- Kraken Lab con scenari di regressione end-to-end.

**Uscita:** una catena completa scanner → brute force → login esca → comandi →
download → canary → blocco IP + incidente + report, con rollback provato.

## Fase 5 — 5.0: solo soglie misurate

Non è una release automatica. Si apre solo se un pilot reale mostra il bisogno:

- carico di prova **500 agenti / 2.000 ev/s** sostenuto, non simulato in un
  solo processo;
- Kafka/Redpanda solo oltre 50.000 ev/s, 20 consumer group indipendenti o
  replay storico > 7 giorni;
- Kubernetes/Helm solo oltre 5 nodi o autoscaling/multi-tenant reale;
- multi-tenancy solo per MSSP, con isolamento e backup provati.

Se le soglie non sono raggiunte, la 5.0 non si fa: si continua a migliorare la
4.x. Il numero non è un premio per aver finito una milestone.

## KPI di avanzamento

- detection: precision/recall/F1 e FP per host/giorno sul corpus, più MTTD e
  MTTA live;
- pipeline: p95 ingestione, lag outbox, eventi persi/duplicati, error rate;
- Kraken: tempo di detonazione, sample eliminati/verificati, alert per
  sessione, falsi positivi da scanner;
- endpoint: RSS/CPU per profilo, dimensione del binario, tempo di
  installazione/upgrade, eventi duplicati e parità funzionale;
- risposta: tempo di contenimento, rollback riusciti, azioni senza TTL;
- release: tempo dal tag al download verificato, asset mancanti, firma.

## Rischi da tenere aperti

1. **Malware escape:** la sandbox non deve avere rete verso Internet, socket o
   volumi condivisi; ogni scenario Lab resta su reti isolate.
2. **Scope creep:** la 4.2 non è “tutto Kraken”; se una capacità non ha test e
   accettazione, slitta.
3. **Deception rumorosa:** ogni regola deve avere un negativo; le soppressioni
   hanno TTL e report.
4. **Bus factor:** i runbook e la CI sono parte della release, non documenti
   opzionali.
5. **Firma assente:** fino a cosign, la release è integra rispetto al download,
   non autentica rispetto al publisher. Va detto, non nascosto.
6. **Rewrite senza parità:** un agente Go che perde ETW, FIM, YARA o
   remediation non è un miglioramento; la matrice di parità è un gate.
7. **Doppio agente in migrazione:** due servizi sullo stesso host possono
   duplicare eventi e confondere la revoca; la migrazione va provata prima
   del pilot.
8. **CGO e sicurezza:** YARA e parte delle API native possono reintrodurre
   codice C; vanno isolati, scansionati e testati, non considerati “Go quindi
   sicuro”.

## Primi 10 giorni di lavoro

1. Chiudere il debito di release: nome `env.example`, NodeTrace Windows nel job
   di release, smoke nel tag.
2. Scrivere il test di regressione per 4.2.1 e il contratto batch da 500.
3. Implementare 4.2.1 e la metrica `outbox_lag_seconds`.
4. Aprire la PR della timeline 4.2.3 con il benchmark 10k eventi.
5. Solo dopo: iniziare le regole Sigma 4.2.2.
6. Congelare le nuove feature su Guard/NodeTrace; aprire solo fix di sicurezza,
   compatibilità, CI e release.
7. Scrivere la matrice di parità e l'ADR dell'agente unico, senza codice di
   prodotto: serve a stimare la 4.3, non a iniziarla dentro la 4.2.
