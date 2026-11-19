# Piano post-4.3 — Network Sensor, qualità del sensore, delivery e Fleet

**Stato:** proposta tecnica del 2026-11-19, pronta per approvazione.
**Non è una dichiarazione di capacità già implementata.**

**Regola 4.3:** la 4.3 è in feature freeze. I punti 1–6 del gate di release
(load, restart, bundle, upgrade/rollback, CI al tag, clean install) sono
lavoro di release, non nuove feature. Firewall e DNS policy entrano nella 4.5
(Network Visibility), non nella 4.3.
**Fonti:** `docs/PLAN_V4.3.md`, `docs/ROADMAP.md`, codice `aegis-agent`,
`aegis-brain`, `aegis-link`.

---

## 1. Decisione: router e network sensor sono due cose diverse

`router` descrive **dove** metti un sensore, non **cosa** sa fare un agente.

Il profilo `router` attuale è un placeholder di laboratorio: viene accettato dal
binario Go ma ricade nel ramo `sensor`; non fa packet capture, non vede il
traffico degli altri host, non configura nftables/DNS e non ha un pacchetto
OpenWrt. Non è il network sensor che serve per monitorare una LAN.

Il network sensor è un **prodotto separato**:

- binario, servizio e artefatto `aegis-net-sensor`;
- `agent_type=network-sensor`, non `router`, non `unified`;
- stesso repository e stessi contratti condivisi (event schema, identità,
  trasporto, OTA), ma senza il runtime Guard/endpoint;
- due modalità di collocazione, non due tipi di agente:
  - **gateway**: installato sul router/gateway che instrada o NATta il traffico;
  - **SPAN/TAP**: installato su un host Linux collegato a una porta mirror.

La modalità gateway è quella che interessa il router. La modalità SPAN/TAP è
quella corretta quando il router non può ospitare il sensore o quando serve una
copia completa del traffico.

### 1.1 Cosa vede e cosa non vede

| Collocazione | Vede | Non vede |
|---|---|---|
| Agente endpoint su un host | processi, file, FIM, ETW/eBPF, risposta locale | traffico degli altri host, processi remoti |
| Network sensor su gateway | traffico routed/NATted, DNS/DHCP se gestiti dal router, inventario di rete | traffico switched che non passa dal gateway, payload TLS, processi/file remoti |
| Network sensor su SPAN/TAP | copia del traffico della porta mirrorata | processi/file, traffico non mirrorato, payload TLS |

Quindi:

- **network visibility**: network sensor;
- **EDR e response**: endpoint/unified;
- **router come unico punto di installazione**: solo se è gateway o riceve una
  copia del traffico. Non è possibile vedere magicamente tutti i dispositivi
  senza una progettazione di rete.

### 1.2 Perché è la scelta migliore per Aegis

1. **Non sporca `unified`.** `unified` significa endpoint + sensor sullo stesso
   host. Aggiungere packet capture, nftables e un ciclo di vita OpenWrt a quel
   profilo renderebbe il pacchetto endpoint più grande, più privilegiato e più
   difficile da certificare.
2. **Ha un modello di rischio diverso.** Un gateway vede traffico di terzi:
   privacy, retention, anonimizzazione e consenso non sono gli stessi di un
   agente che legge solo il proprio host.
3. **Ha un packaging diverso.** MSI/deb/rpm per endpoint; opkg/apk e UCI per
   OpenWrt; systemd per gateway Linux. Un solo artefatto non è credibile.
4. **Ha una release diversa.** L'endpoint 4.3 è già in cutover. Il network
   sensor è una linea 4.5: non deve bloccare la chiusura di AP-115.
5. **Mantiene i contratti condivisi.** Event schema, identità, trasporto,
   outbox e OTA possono essere riusati; non si duplica il Brain.

**Non** è la scelta migliore creare un quarto profilo `router` dentro
`aegis-agent`: sarebbe un fork mascherato da configurazione, con dipendenze
native e test che non hanno nulla a che vedere con l'endpoint.

---

## 2. Roadmap

### 2.1 Release

- **4.3** — chiusura dell'agente unico Go; network sensor **fuori perimetro**.
- **4.4** — response intelligence, invariata.
- **4.5** — Network Visibility: `aegis-net-sensor`, gateway/SPAN, inventory,
  flow/DNS, detection e policy.
- **4.3.x** — hardening del sensore, delivery e packaging: lavoro di
  manutenzione, non nuove feature endpoint.

### 2.2 Fasi Network Sensor (4.5)

#### N0 — ADR, threat model, hardware matrix

- ADR: perché un binario separato; dati raccolti; modalità supportate.
- Threat model: traffico di terzi, privacy, retention, accesso root/capability,
  rischio di blocco del forwarding.
- Hardware: Linux x86_64/ARM64; OpenWrt solo target dichiarati (RAM, storage,
  kernel, nftables).
- Decisione esplicita: metadata di default; PCAP opt-in con ring buffer.

**Uscita:** ADR approvato e matrice hardware pubblicata. Nessun codice di
policy prima di questa uscita.

#### N1 — Collector passivo

- conntrack/nftables + AF_PACKET/eBPF su Linux gateway;
- AF_PACKET/libpcap su SPAN/TAP;
- flow record: 5-tuple, byte, pacchetti, direzione, NAT, MAC, VLAN, timestamp;
- DNS/DHCP/ARP/NDP per identità di rete;
- contatori di drop e copertura.

**Uscita:** un host di test è visibile in inventario anche senza agente
endpoint; il sensor dichiara cosa non vede.

#### N2 — Detection e inventario

- scan, beaconing, esfiltrazione, DNS tunneling, talker anomali, IOC;
- detection versionate, allowlist e baseline per sito/VLAN;
- correlazione con alert endpoint quando lo stesso IP/MAC è noto;
- niente auto-remediation: dry-run e approvazione.

**Uscita:** detection con test positivi/negativi e falsi positivi misurati.

#### N3 — Policy di rete

- nftables/ipset con TTL, scope, dry-run, approvazione, audit e rollback;
- DNS sinkhole solo se il resolver è gestito;
- inline/NFQUEUE opzionale, mai default;
- fail-open sul forwarding: se il sensor cade, la rete continua a funzionare.

**Uscita:** blocco applicato e rimosso con evidenza; nessun blocco permanente
dopo un errore.

#### N4 — Packaging e deployment

- deb/rpm con systemd per gateway Linux;
- opkg/apk con init script e UCI per OpenWrt;
- upgrade/rollback firmato, health, watchdog;
- nessun `.ps1`/`.sh` come percorso di produzione.

**Uscita:** install pulita su Linux e su un target OpenWrt dichiarato.

#### N5 — UI Network

- vista separata `Network`, non dentro il rollout endpoint;
- inventario IP/MAC/hostname/VLAN, flow, DNS, detection, policy;
- badge `passive`/`inline`, copertura e drop;
- nessun pulsante endpoint (kill/quarantine) su un network sensor.

**Uscita:** un analista capisce se sta guardando un host o un segmento di rete.

---

## 3. Hardening del sensor host (4.3.x)

Il profilo `sensor` è telemetry-only. Questo è corretto per least privilege, ma
oggi il limite non è abbastanza esplicito e la qualità del dato è povera.

### 3.1 Enrichment DNS e flow

- cache DNS/SNI e reverse DNS **asincrono**, con timeout e provenienza;
- nessun lookup sincrono per ogni flow;
- flow con processo/PID quando il traffico è locale, altrimenti `unknown`
  esplicito;
- metriche: flow risolti, unresolved, latenza, timeout.

### 3.2 Detection quality

Le euristiche attuali sono troppo strette:

- CPU > 80% **solo** con porte miner note;
- almeno 10 connessioni verso lo stesso IP;
- LOLBin con memoria > 5%.

Vanno sostituite o affiancate da:

- baseline/EWMA per host e processo;
- allowlist e prevalenza;
- detection con ID, versione, confidenza e motivazione;
- test di replay e misura dei falsi positivi.

### 3.3 Limite di response

Il sensor non deve uccidere, isolare o bloccare. Deve:

- dichiarare `telemetry-only` nelle capability e in UI;
- non mostrare azioni che il Brain invierà e l'agente rifiuterà;
- lasciare la response a `endpoint`/`unified` o a un network sensor con policy
  di rete esplicita.

### 3.4 Test e misure

- flow benigni/maliziosi e assenza di DNS;
- overhead CPU/RSS prima/dopo su Windows e Linux;
- percentuale di flow risolti, non una stima;
- soak e restart.

---

## 4. Link, Redis e perdita di dati

> **Stato al 2026-11-19.** Lo spool durevole Link, il `Retry-After`, il claim
> atomico con processing/ack e la DLQ sono implementati. AP-122 ha ora
> evidenza live 50k (50.000 accepted, 1 × 429, LLEN 50.000, zero 5xx). AP-123
> ha un restart a livello di processo (worker che esce senza ack, secondo
> processo che recupera `attempt=2`) e la UI OTA distingue esplicitamente
> `queued — not executed` dall'ack di esecuzione. La fonte di verifica è
> `docs/RELEASE_GATE_4.3.md` e `docs/benchmarks/4.3/link-load-50k.md`.

### 4.1 Percorso reale oggi

- **Go sensor e Go endpoint**: telemetria e comandi direttamente al Brain.
- **`aegis-link`**: gateway Spring Boot per eventi/syslog/legacy/shipper, che
  scrive in `aegis:events`; il Brain consuma con `BRPOPLPUSH`.
- **Comandi**: il Brain accoda in `aegis:commands:<agent_id>`; l'agente legge
  dal Brain, che fa claim atomico (Lua) e sposta il comando in processing. Link
  usa lo stesso contratto per gli agenti legacy.

Quindi la frase “l'agente passa prima dal Link con Redis” non è vera per il Go.
Non è nemmeno “solo l'endpoint”: **né sensor né endpoint Go passano dal Link**.
Il Link resta un percorso separato, non il critical path dell'agente nuovo.

### 4.2 Cosa succedeva con il 429 del Link (prima del fix)

`IngestionController` aveva `MAX_QUEUE_SIZE = 50000` e faceva:

1. `getQueueSize()`;
2. se >= 50000, rispondeva **429**;
3. altrimenti `pushEvent()` su Redis.

Il 429 **non metteva l'evento in una coda di attesa e non lo conservava**: il
server lo rifiutava prima del push. Non era una perdita silenziosa lato server,
ma era una perdita definitiva se il mittente non ritentava. Non c'era
`Retry-After` e il percorso syslog/UDP non poteva ritentare.

Oggi, se la coda è piena o Redis è irraggiungibile, Link scrive un file nello
spool durevole e risponde `202 spooled`; se anche lo spool non è disponibile
risponde `429` con `Retry-After`. Il check+push è **atomico** (Lua
`LLEN`+`LPUSH`): il `202` viene restituito solo se Redis o lo spool hanno
accettato l'evento. Resta da fare il test di carico con producer concorrenti;
il cap non è “dati al sicuro”, è un tetto anti-OOM. AP-122 è in Test, non Done.

### 4.3 Cosa succedeva con i comandi (prima del fix)

`enqueue_command` faceva `LLEN`, poi `RPUSH`, poi `LTRIM -limit -1`:

- due producer possono superare il cap;
- il trim tiene i più recenti e può scartare un comando precedente;
- il Brain/Link leggono con `LPOP`: se l'agente muore dopo il pop e prima
  dell'esecuzione/ack, il comando è perso;
- diversi call-site non propagano `queued=False` e possono mostrare successo.

Quindi, prima del fix, i comandi erano **at-most-once**, non at-least-once. Per
un contenimento era un rischio reale. Ora Brain e Link usano uno script Lua
atomico, processing list, visibility timeout, ack idempotente e DLQ; la
garanzia è at-least-once.

### 4.4 Obiettivo

- **Telemetria endpoint**: outbox locale con retry; il 429 del Brain è
  ritentabile. Lo spool ha un limite e il drop da spool pieno deve essere
  contato.
- **Link**: se resta un percorso di ingestion, deve avere un contratto
  esplicito: `Retry-After`, body `queue_full`, metrica, test di carico del
  check+push atomico e, per i flussi che devono sopravvivere a Redis pieno,
  buffer locale persistente. Syslog UDP resta at-most-once per natura e va
  dichiarato.
- **Comandi**: processing list + ack + requeue, idempotency key, cap atomico,
  `queue_full` propagato come 503/202 esplicito.

**Regola:** non si dichiara “nessuna perdita” finché non c'è un test che
uccide il consumer, riempie la coda e verifica il contatore.

---

## 5. Deploy senza `.ps1`/`.sh`

Il one-liner resta un fallback di laboratorio. La produzione usa pacchetti:

- **Windows**: MSI/MSIX firmato Authenticode, servizio nativo;
- **Linux**: deb/rpm firmato, systemd, repository apt/dnf;
- **OpenWrt**: opkg/apk firmato, init script, UCI;
- **macOS**: solo se il perimetro lo richiede; pkg/launchd, non parità EDR
  senza EndpointSecurity;
- **enrollment**: token monouso da file/CLI o MDM, non `irm|iex`/`curl|bash`;
- **artefatto**: `unified` in CI con checksum, SBOM, manifest Ed25519 e
  provenance;
- **air-gapped**: bundle offline e verifica firma.

Il pacchetto non firmato va dichiarato “non firmato”, mai “signed”.

---

## 6. UI Fleet

La distinzione concettuale resta:

- **Inventory**: cosa c'è, IP/MAC/hostname, stato agenti, copertura;
- **Rollout**: token, package, job, canary, rollback;
- **Artifacts & OTA**: versioni, checksum, firma, SBOM, update.

La UI attuale duplica il deploy tra Discovery e Deploy. La destinazione è una
sola area **Fleet** con tre tab/step, mantenendo API e permessi separati.
I network sensor stanno in `Network`, non in `Fleet` endpoint: un host senza
agente non è un endpoint mancante.

---

## 7. Fuori perimetro

- IDS/IPS completo con motore di firme proprio;
- decifratura TLS;
- blocco inline di default;
- packet capture continuo con payload;
- agente endpoint sul router al posto del network sensor;
- sostituire l'endpoint con il network sensor.

---

## 8. Mappa ticket

I ticket operativi sono nel progetto YouTrack `AP`; questo documento è la
fonte di perimetro, non il sostituto del ticket.

| Track | Ticket |
|---|---|
| Network Sensor: ADR e collector passivo | AP-118 — `AEGIS-NETSENSOR-01` |
| Network Sensor: inventario e detection | AP-119 — `AEGIS-NETSENSOR-02` |
| Network Sensor: policy e packaging | AP-120 — `AEGIS-NETSENSOR-03` |
| Sensor host: DNS/flow e detection quality | AP-121 — `AEGIS-SENSOR-01` |
| Link: 429, retry e durabilità | AP-122 — `AEGIS-LINK-01` |
| Comandi: cap atomico e at-least-once | AP-123 — `AEGIS-CMD-01` |
| Validazione malware reale e detonatore isolato | AP-126 — `AEGIS-DETON-01` |
| Qualità detection: riduzione FP/FN | AP-127 — `AEGIS-DET-QUALITY-01` |
| Packaging firmato senza script | AP-124 — `AEGIS-DEPLOY-01` |
| UI Fleet unificata | AP-125 — `AEGIS-UX-01` |

AP-122 e AP-123 sono in **Test** (implementazione presente, verifica di
release ancora aperta); AP-126/AP-127 sono in **Backlog** e appartengono alla
live validation post-4.3. Nessuno è `Done`.

Ticket già esistenti correlati: **AP-114** (perimetro router/cutover),
**AP-115** (gate produzione), **AP-116** (unified), **AP-117** (deploy first
boot). AP-114 va letto con la correzione di questo documento: il profilo
`router` non è il network sensor.
