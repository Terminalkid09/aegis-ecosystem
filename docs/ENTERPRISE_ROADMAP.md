# Aegis Enterprise Roadmap

## Obiettivo

Portare Aegis da prototipo avanzato a piattaforma EDR/XDR dimostrabile in un contesto SOC aziendale, con:

- sensori Windows e Linux affidabili;
- pochi alert, correlati e spiegabili;
- dashboard multi-sito e multi-ruolo;
- enrollment sicuro senza SSH obbligatorio;
- installazione on-premise ripetibile;
- aggiornamenti firmati e rollback;
- misure oggettive di qualità, prestazioni e sicurezza.

Il progetto deve rimanere indipendente: il confronto con prodotti o aziende esterne serve a definire capacità e benchmark, non a replicare codice, documentazione riservata o proprietà intellettuale altrui.

## Principi non negoziabili

1. **Evidence first**: ogni detection deve avere eventi, causa, confidenza e catena temporale leggibili.
2. **Fail closed per la sicurezza**: autenticazione, enrollment, revoca e aggiornamenti non devono degradare silenziosamente.
3. **Least privilege**: agent e backend usano privilegi diversi e solo quando necessari.
4. **Privacy by design**: raccolta configurabile, retention esplicita e minimizzazione dei dati.
5. **No alert singolo senza contesto**: un evento sospetto non equivale automaticamente a un incidente.
6. **Misurazione prima del marketing**: precision, recall, falsi positivi per host/giorno, latenza e overhead devono essere misurabili.
7. **Riproducibilità**: ogni release deve poter essere installata, testata, aggiornata e rollbackata da zero.

## Stato di partenza

Componenti già presenti:

- `aegis-brain`: API, autenticazione, regole, correlazione, incidenti, deploy e servizi di supporto;
- `aegis-guard`: agent Java con outbox eventi e gestione locale;
- `NodeTrace`: agent Python/eBPF e telemetria;
- `aegis-ebpf`: collector e contratto eventi;
- frontend React/Vite;
- Docker Compose e installer Linux/Windows;
- test unitari, integrazione e schema eventi.

Prima di ogni milestone bisogna creare una baseline con test, build, versione, hash degli artefatti e stato Git. Nessun lavoro deve cancellare modifiche locali dell’utente.

## Milestone 0 — Baseline e threat model

### Obiettivi

- congelare il perimetro della prima release enterprise;
- definire asset, attori, trust boundary e scenari d’attacco;
- separare chiaramente demo, laboratorio e produzione;
- scegliere le versioni OS supportate.

### Decisioni richieste

- Windows 10/11 e quali Windows Server;
- Ubuntu/Debian/RHEL e versione minima kernel/eBPF;
- deployment solo on-premise nella prima fase;
- retention e dati consentiti: command line, username, path, hash, destinazioni di rete;
- modello single-tenant iniziale oppure organizzazione/siti già separati.

### Criteri di completamento

- threat model versionato;
- matrice dei rischi con owner e priorità;
- matrice compatibilità OS/kernel;
- inventario delle API e dei flussi di autenticazione;
- baseline automatica verde o con eccezioni documentate.

## Milestone 1 — Contratto eventi e affidabilità del sensore

### Event schema v2

Standardizzare ogni evento con:

- `event_id`, `schema_version`, `agent_id`, `boot_id`;
- timestamp wall-clock e timestamp monotono;
- sequence number per rilevare duplicati e perdite;
- processo, parent process, PID e process start time;
- utente, sessione, integrità e privilegi;
- path canonico, hash, firma e publisher quando disponibili;
- endpoint di rete, protocollo e direzione;
- container, namespace e cgroup su Linux;
- provenienza, qualità, sampling e motivo di eventuale drop.

### Pipeline locale

- coda persistente cifrata;
- backpressure e limiti di spazio;
- retry con jitter e idempotenza;
- deduplicazione controllata;
- contatori esposti per eventi persi, ritardi e queue saturation;
- comportamento definito quando il server è irraggiungibile;
- protezione anti-tamper e log locali diagnostici senza dati eccessivi.

### Criteri di completamento

- schema validato in CI;
- compatibilità backward/forward documentata;
- test di perdita rete, reboot, clock drift, disco pieno e duplicazione;
- perdita evento misurata e non invisibile;
- overhead CPU/RAM/disk documentato per profilo sensore.

## Milestone 2 — Sensore Windows

### Telemetria prioritaria

- process creation/termination e lineage completo;
- ETW per processi, image load e network dove disponibile;
- AMSI e PowerShell ScriptBlock;
- servizi, scheduled task, WMI e startup locations;
- Registry autorun e modifiche sensibili;
- accesso a LSASS, token e privilege escalation indicators;
- driver, Defender exclusions e tentativi di disabilitare il sensore;
- connessioni di rete associate al processo;
- firma Authenticode, hash e prevalenza locale.

### Qualità

- normalizzare command line e path;
- distinguere processo appena avviato da processo riutilizzato;
- gestire PID reuse usando start time;
- evitare polling aggressivo;
- degradare con feature flag quando una sorgente non è disponibile;
- telemetria esplicita della copertura reale.

### Criteri di completamento

- replay di eventi benigni e simulati;
- test su Windows supportati;
- nessun crash del servizio in caso di sorgente ETW indisponibile;
- installazione, upgrade, uninstall e rollback verificati;
- overhead entro una soglia definita e pubblicata.

## Milestone 3 — Sensore Linux

### Telemetria prioritaria

- eBPF per exec/exit, file, network, credenziali e process lifecycle;
- auditd come fallback mirato, non come duplicatore indiscriminato;
- systemd, cron, SSH keys, shell profile e startup persistence;
- moduli kernel, capabilities, namespace, cgroup e container;
- accesso a secret file e modifiche a configurazioni critiche;
- connessioni con processo, UID, namespace e container associati.

### Compatibilità

- probe di capability del kernel all’avvio;
- profili per kernel con BTF/eBPF completo, parziale o assente;
- pacchetto e servizio systemd;
- gestione root/helper limitata alle operazioni necessarie;
- fallback dichiarati e visibili in dashboard.

### Criteri di completamento

- test su almeno una distribuzione Debian-family e una RHEL-family;
- test kernel compatibili e non compatibili;
- golden events versionati;
- benchmark con e senza attività intensa;
- nessun blocco del sistema causato dal collector.

## Milestone 4 — Detection engineering e riduzione dei falsi positivi

### Strati di decisione

1. evento osservato;
2. indicatore debole;
3. comportamento anomalo rispetto alla baseline;
4. sequenza sospetta;
5. incidente correlato;
6. risposta automatica solo con confidenza e policy sufficienti.

### Evidenze da usare

- parent-child lineage;
- firma e publisher;
- prevalenza del file nel tenant e nel sito;
- ruolo dell’utente e del dispositivo;
- first-seen/last-seen;
- reputazione hash e destinazione;
- persistenza e modifica di policy;
- rarità combinata con catena temporale;
- feedback analyst e soppressioni con scadenza.

### Regole

- identificatore e versione per ogni regola;
- mapping ATT&CK quando appropriato;
- severità e confidence separate;
- motivazione human-readable;
- test positivi e negativi per ogni detection;
- canary rollout e rollback delle regole;
- audit di chi modifica o disabilita una regola.

### Criteri di completamento

- replay engine deterministico;
- corpus benigno e corpus di tecniche sospette;
- KPI: precision, recall, F1, false positives/host/day, MTTD e triage time;
- report automatico prima di ogni release;
- nessuna risposta distruttiva automatica nella modalità demo.

## Milestone 5 — Correlazione e incident response

- grafo host-process-user-network-file;
- finestre temporali configurabili;
- deduplica di alert simili;
- incidenti con timeline e root cause ipotizzata;
- stato, assegnatario, note e feedback dell’analista;
- playbook dry-run, approvazione e audit;
- isolamento host come operazione esplicita e reversibile;
- raccolta di evidenze senza modificare inutilmente il sistema.

Ogni automazione deve avere precondizioni, livello di rischio, approvatore e rollback.

## Milestone 6 — Enrollment e deploy remoto sicuro

### Flusso

1. admin crea un enrollment request dalla dashboard;
2. Aegis genera token monouso con scadenza breve;
3. l’utente/admin esegue il bootstrap locale o usa GPO/Intune/Ansible;
4. il bootstrap verifica firma e checksum dell’artefatto;
5. l’agent genera la chiave localmente;
6. il server approva e rilascia certificato mTLS;
7. l’agent entra nel gruppo/sito assegnato;
8. dashboard mostra stato, versione e health.

### Regole di sicurezza

- mai fidarsi del solo IP;
- token monouso, breve e revocabile;
- certificati per-device;
- revoca e rotazione certificate;
- manifest firmato e repository versionato;
- no `curl | bash` senza verifica;
- approvazione RBAC e audit trail;
- rate limit e protezione brute force;
- impossibilità di cambiare server tramite configurazione non autenticata.

### Criteri di completamento

- installazione Linux e Windows da zero;
- enrollment approvato e rifiutato;
- token scaduto, riutilizzato e revocato;
- certificato revocato e rinnovato;
- upgrade fallito con rollback;
- device duplicato o reimaged gestito correttamente;
- nessuna credenziale statica incorporata negli installer.

## Milestone 7 — Dashboard SOC e modello organizzativo

- tenant/organization;
- siti, subnet e gruppi;
- ruoli admin, SOC analyst, responder, auditor e viewer;
- separazione dei permessi per visualizzazione, regole, deploy e isolamento;
- filtri host/user/site/severity/confidence;
- stato agent online/offline/stale;
- dashboard di salute del sensore e qualità dati;
- incident timeline ed evidence drawer;
- audit log append-only con retention configurabile.

La dashboard non deve mostrare solo alert: deve mostrare anche copertura, eventi persi, agent obsoleti e sensori degradati.

## Milestone 8 — Produzione on-premise

### Prima modalità supportata

Docker Compose con:

- backend;
- frontend/reverse proxy;
- PostgreSQL;
- Redis;
- worker;
- backup e restore;
- health/readiness/liveness;
- secrets esterni al repository;
- log strutturati e rotazione.

### Kubernetes

Helm è una seconda modalità, non un prerequisito. Dovrà includere:

- values sicuri e validazione;
- secret management documentato;
- persistence e backup;
- ingress/TLS;
- probes e resource limits;
- migration job;
- upgrade e rollback;
- test su cluster locale prima di qualunque cloud.

## Milestone 9 — Cloud opzionale

Il primo scenario resta on-premise. Cloudflare Tunnel può esporre dashboard/API senza aprire porte inbound, ma non sostituisce backend, database o message broker.

Eventuale cloud control plane futuro:

- tenant metadata minima;
- relay di enrollment;
- nessun invio implicito di telemetria sensibile;
- cifratura e retention dichiarate;
- modalità completamente disconnessa per clienti regolamentati.

Non migrare PostgreSQL/Redis/telemetria su un servizio diverso solo per usare un piano gratuito: prima servono benchmark di volume, costi e affidabilità.

## Milestone 10 — CI, sicurezza e supply chain

- lint, type check, unit e integration test;
- schema compatibility test;
- SAST, dependency audit e secret scan;
- SBOM per ogni release;
- immagini con digest pinning;
- firma degli artefatti;
- provenance del build;
- scansione container;
- test installazione in ambiente pulito;
- release notes e migration notes;
- gestione CVE con SLA e severity.

## Definition of Done per ogni modifica

Una modifica è completa solo se:

1. ha test automatici o una motivazione documentata;
2. non rompe compatibilità non dichiarate;
3. ha logging e metriche sufficienti;
4. è stata testata nel percorso di errore;
5. non introduce segreti o dati sensibili nei log;
6. aggiorna documentazione e changelog;
7. ha rollback o piano di recupero;
8. passa build, test e controllo diff;
9. produce un risultato verificabile;
10. aggiorna il registro dei rischi se cambia il threat model.

## Ordine pratico di implementazione

1. baseline e threat model;
2. schema eventi v2 e pipeline affidabile;
3. Windows sensor hardening;
4. Linux sensor hardening;
5. replay engine e KPI detection;
6. correlazione e incident timeline;
7. enrollment mTLS e installer firmati;
8. dashboard multi-site/RBAC/audit;
9. Compose production package;
10. upgrade/rollback e backup/restore;
11. test pilot con pochi endpoint;
12. Helm/Kubernetes opzionale;
13. Cloudflare Tunnel opzionale.

## Piano di verifica finale

### Funzionale

- installazione pulita Windows/Linux;
- enrollment, revoca, rinnovo e uninstall;
- eventi correttamente visualizzati;
- incidente correlato da più eventi;
- isolamento e rollback;
- backup e restore;
- aggiornamento agent e backend.

### Sicurezza

- token replay;
- brute force enrollment;
- certificato revocato;
- privilege escalation dell’agent;
- tampering della coda locale;
- manifest alterato;
- accesso cross-tenant;
- CSRF, session fixation e websocket authorization;
- injection nei log e nelle query;
- secrets presenti negli artefatti.

### Prestazioni

- endpoint inattivo;
- endpoint ad alta attività;
- rete intermittente;
- server con più agent simultanei;
- crescita database e retention;
- latenze di ingestione e correlazione;
- CPU/RAM/disk dell’agent.

## Handoff per altri modelli

Prima di passare il lavoro a un altro modello, fornire sempre:

```text
Repository: aegis-ecosystem
Branch: <branch>
Milestone corrente: <M0-M13>
Obiettivo del task: <una frase>
File già modificati: <elenco>
Vincoli: non fare reset, preservare modifiche locali, non introdurre segreti
Comandi già eseguiti: <elenco e risultati>
Test da eseguire: <elenco>
Definition of done: <criteri puntuali>
Problemi aperti: <elenco>
```

Prompt consigliato:

> Lavora nel repository `aegis-ecosystem` sulla milestone `<X>`. Leggi prima `docs/ENTERPRISE_ROADMAP.md` e lo stato Git. Non fare reset o checkout distruttivi e preserva le modifiche esistenti. Implementa solo il task indicato, aggiungi test, esegui i test pertinenti, controlla il diff e riporta file modificati, rischi residui e risultati esatti dei comandi.

## Posizionamento del progetto

Aegis può diventare un ottimo progetto da mostrare a un SOC o a un’azienda di cybersecurity se presenta:

- demo riproducibile;
- sensori tecnicamente solidi;
- detection spiegabili;
- metriche oneste;
- sicurezza dell’enrollment;
- documentazione chiara;
- limiti dichiarati.

Non bisogna promettere di essere già “migliore” di un prodotto enterprise maturo. L’obiettivo credibile è mostrare una piattaforma indipendente, misurabile e tecnicamente ambiziosa, con una roadmap concreta verso la produzione.
