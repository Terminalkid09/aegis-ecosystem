# Privacy e GDPR — Aegis Ecosystem

Stato: bozza tecnica per Gate 0 (AP-20), 2026-11-15. **Non è un parere
legale.** Prima della distribuzione a clienti il documento e il DPA devono
essere verificati da un legale/DPO competente.

Aegis è distribuito on-premise: il cliente che installa la piattaforma decide
perché e come trattare i dati. Il progetto non gestisce un servizio SaaS e non
riceve telemetria dai deployment dei clienti.

## 1. Ruoli

| Scenario | Titolare | Responsabile | Note |
|---|---|---|---|
| Cliente installa Aegis sui propri endpoint | Cliente | Cliente (o fornitore IT del cliente) | Il progetto non tratta i dati |
| Fornitore IT installa e gestisce Aegis per un cliente | Cliente | Fornitore IT | Serve un DPA tra cliente e fornitore |
| Manutenzione remota del deployment | Cliente | Soggetto che accede su autorizzazione | Accesso minimo, loggato e revocabile |

Il fornitore del software non è responsabile del trattamento solo perché il
codice è installato. Un eventuale supporto remoto va coperto da un accordo
separato e da un accesso tracciato.

## 2. Registro dei trattamenti

| Dato | Finalità | Base giuridica (indicativa) | Conservazione default | Dove |
|---|---|---|---|---|
| Telemetria endpoint: processi, path, hash, username, comandi, rete | Rilevazione e risposta a incidenti di sicurezza | Legittimo interesse alla sicurezza; obblighi di legge se applicabili | 14 giorni | PostgreSQL `telemetry` |
| Alert, incidenti, timeline, note analyst | Triage e risposta | Sicurezza; obblighi di legge | 90 giorni | PostgreSQL `alerts`, `incidents` |
| Audit log di accessi e azioni | Accountability e indagini | Obblighi di sicurezza; legittimo interesse | 365 giorni | PostgreSQL `audit_logs` |
| Syslog | Correlazione sicurezza | Legittimo interesse | 30 giorni | PostgreSQL `syslog_events` |
| Credenziali agent (device secret) | Autenticazione degli endpoint | Esecuzione del contratto/sicurezza | Fino a revoca | Hash in PostgreSQL; cache Redis solo hash |
| Token di enrollment | Registrazione di un host | Sicurezza | 15 minuti, monouso | Hash in PostgreSQL |
| Note VaultX | Segreti operativi del cliente | Esecuzione del contratto | Fino a cancellazione | PostgreSQL cifrato |
| Backup | Continuità operativa e recupero | Sicurezza | 7 giorni | Volume backup cifrato |
| Kraken: eventi di attacco, IP, username/password tentate, comandi | Analisi di attacchi contro honeypot | Legittimo interesse alla sicurezza | 30 giorni / quota 5 GiB | Istanza Kraken separata |
| Kraken: sample malware caricati | Analisi tecnica | Sicurezza; consenso del cliente per dati non necessari | 30 giorni / quota 5 GiB | Archivio sample separato |

I campi “username”, indirizzi IP, hostname e command line possono identificare
persone fisiche. Non sono quindi “dati non personali” solo perché tecnici.

## 3. Minimizzazione e log

- Non registrare password, token, chiavi API o contenuto di file nei log
  applicativi.
- Le password tentate su Kraken sono conservate solo come HMAC con chiave; il
  valore in chiaro non viene scritto su DB, JSONL, SIEM o alert Telegram.
- La telemetria è configurabile e può essere ridotta dal cliente; la retention
  è un limite massimo, non un obbligo a conservare tutto.
- I sample Kraken sono accettati solo entro i limiti di dimensione, numero di
  file e quota; il contenuto non viene eseguito dal Brain.
- I log di debug non vanno abilitati in produzione (`DEBUG=false`).

## 4. Retention e cancellazione

Default:

- telemetria 14 giorni;
- alert e incidenti 90 giorni;
- audit 365 giorni;
- syslog 30 giorni;
- backup 7 giorni;
- Kraken 30 giorni e quota 5 GiB, con overwrite prima dell'unlink.

La retention è configurabile, ma non può essere infinita per default. La purge
deve essere eseguita dopo un backup verificato; l'audit non viene cancellato
automaticamente senza conferma esplicita. Alla cessazione del contratto il
cliente può esportare e cancellare i dati del proprio deployment. I backup
ruotano secondo la retention e vanno distrutti con la stessa procedura.

## 5. Residenza e trasferimenti

- Il deployment è on-premise: i dati restano nell'infrastruttura scelta dal
  cliente.
- Non c'è telemetria inviata al progetto.
- I provider AI cloud sono spenti per default e l'arricchimento automatico è
  disabilitato; se il cliente li abilita, deve verificare sede e garanzie del
  fornitore.
- Le integrazioni OSINT opzionali inviano solo indicatori (IP/dominio), non la
  telemetria completa. Il cliente deve comunque valutarle nel proprio registro.
- I backup vanno conservati nella giurisdizione richiesta dal cliente.

## 6. Diritti degli interessati

Il cliente, in qualità di titolare, gestisce accesso, rettifica, cancellazione,
limitazione, opposizione e portabilità. Il deployment deve permettere almeno:

- ricerca e export dei dati per host/utente e intervallo temporale;
- cancellazione dei dati non più necessari, nel rispetto degli obblighi di
  legge e della catena di custodia;
- anonimizzazione o pseudonimizzazione quando la sicurezza lo consente.

Le richieste vanno indirizzate al titolare del deployment, non al progetto.

## 7. Sicurezza

Misure presenti o richieste al deployment:

- TLS in transito; mTLS per gli agent in profilo prod;
- RBAC e audit delle azioni;
- cifratura dei segreti e dei backup (GPG con passphrase esterna);
- hashing delle credenziali e HMAC delle password tentate su Kraken;
- isolamento della sandbox Kraken e del broker Docker;
- minimizzazione dei dati e retention attiva;
- log senza segreti e senza payload sensibili.

## 8. Data breach

Il fornitore del deployment deve avere una procedura per:

1. contenere e verificare l'evento;
2. preservare le evidenze senza raccogliere dati ulteriori;
3. notificare il titolare senza ingiustificato ritardo e comunque entro 24 ore
   dalla conferma, per consentire la notifica all'autorità entro 72 ore;
4. documentare impatto, categorie di dati, misure e comunicazioni.

Il progetto riceve segnalazioni di vulnerabilità tramite `SECURITY.md`, non
tramite issue pubbliche con dati personali.

## 9. DPIA

Valutare una DPIA quando il deployment comporta:

- monitoraggio sistematico su larga scala dei dipendenti;
- trattamenti innovativi o ad alto rischio;
- dati particolari o giudiziari;
- interconnessione di fonti o trasferimenti extra-UE;
- decisioni automatizzate con effetti significativi.

La DPIA è responsabilità del titolare; questa bozza fornisce l'inventario di
partenza, non la conclusione.

## 10. Kraken: separazione

Kraken è un servizio distinto con database e archivio sample propri. Non
condivide il database Aegis e non deve essere esposto sulla stessa rete
dell'istanza di management. I dati degli attaccanti sono conservati solo per
l'analisi dell'attacco, con retention e quota, e non vanno usati per finalità
diverse (per esempio marketing o addestramento di modelli) senza una base
giuridica autonoma.

## 11. Documenti collegati

- [`DPA_TEMPLATE.md`](DPA_TEMPLATE.md)
- [`archive/TRADEMARK_RESEARCH.md`](archive/TRADEMARK_RESEARCH.md)
- [`OPERATIONS.md`](OPERATIONS.md) — retention e backup
- [`../SECURITY.md`](../SECURITY.md) — segnalazione vulnerabilità

## 12. Limiti di questa bozza

Non sostituisce un registro dei trattamenti firmato, una DPIA, un parere
legale o un DPA negoziato. I retention default vanno confermati dal cliente e
allineati agli obblighi locali. Le integrazioni cloud opzionali richiedono una
valutazione separata.
