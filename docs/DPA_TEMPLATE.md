# Data Processing Agreement — template

**Template, non parere legale.** Da adattare alla legge applicabile e far
verificare a un legale prima della firma. I campi tra `[ ]` vanno compilati.

## 1. Parti

- **Titolare:** [RAGIONE SOCIALE], sede [ ], P.IVA [ ], rappresentata da [ ].
- **Responsabile:** [RAGIONE SOCIALE], sede [ ], P.IVA [ ], rappresentata da [ ].

## 2. Oggetto e durata

Il Responsabile tratta i dati personali necessari a [installare/gestire/
assistere] il deployment Aegis presso il Titolare, per la durata del contratto
[X] e fino alla restituzione/cancellazione dei dati.

## 3. Ruoli e istruzioni

Il Titolare è il titolare del trattamento. Il Responsabile tratta i dati solo
su istruzioni documentate del Titolare, salvo obblighi di legge. Le istruzioni
iniziali sono nell'Allegato A (categorie di dati, finalità, retention).

Il Responsabile informa immediatamente il Titolare se un'istruzione viola la
normativa applicabile.

## 4. Riservatezza

Il personale autorizzato è vincolato a riservatezza, riceve accesso minimo e
formazione, e usa credenziali nominali. L'accesso remoto è registrato e
revocabile.

## 5. Misure di sicurezza

Al minimo:

- cifratura in transito (TLS; mTLS per gli agent in produzione);
- cifratura dei backup e delle credenziali;
- RBAC, autenticazione forte per gli amministratori e audit log;
- segregazione degli ambienti e dei dati Kraken;
- minimizzazione, retention e cancellazione verificabile;
- gestione degli incidenti e delle vulnerabilità;
- nessun segreto o dato personale non necessario nei log.

## 6. Sub-responsabili

Il Responsabile non nomina sub-responsabili senza autorizzazione scritta del
Titolare. Autorizzati: [ELENCO; “nessuno” se non applicabile]. Per ciascuno
valgono obblighi equivalenti; il Responsabile resta responsabile verso il
Titolare.

## 7. Trasferimenti

I dati restano nel deployment on-premise del Titolare. Eventuali trasferimenti
extra-UE richiedono istruzione scritta, base giuridica e garanzie adeguate
(SCC/decisione di adeguatezza). Provider cloud opzionali: [NESSUNO / ELENCO].

## 8. Assistenza

Il Responsabile assiste il Titolare, per quanto possibile, nel rispondere alle
richieste degli interessati, nelle valutazioni d'impatto e nelle consultazioni
con l'autorità. Le richieste vanno inoltrate a [CONTATTO PRIVACY] entro [5]
giorni lavorativi.

## 9. Data breach

Il Responsabile notifica al Titolare senza ingiustificato ritardo e comunque
entro **24 ore** dalla conferma, con:

- natura dell'evento e categorie di dati interessate;
- host/utenti e volume stimato;
- misure di contenimento adottate;
- rischio residuo e raccomandazioni.

Il Titolare decide la notifica all'autorità entro 72 ore, salvo diverso obbligo
di legge.

## 10. Restituzione e cancellazione

Alla cessazione il Responsabile restituisce i dati in formato [JSON/SQL/altro]
e cancella quelli presenti nei propri sistemi entro [30] giorni, salvo
conservazione obbligatoria. I backup ruotano entro [7] giorni. La cancellazione
è attestata per iscritto; restano possibili copie immutabili di sicurezza fino
alla scadenza della retention.

## 11. Audit

Il Titolare può verificare il rispetto del DPA con [questionario/audit] e
preavviso di [10] giorni, senza accedere a dati di altri clienti. Il
Responsabile fornisce evidenze di configurazione, backup/restore e audit.

## 12. Responsabilità e legge applicabile

Responsabilità: [LIMITI COERENTI CON IL CONTRATTO PRINCIPALE]. Legge: [LEGGE].
Foro: [FORO]. In caso di conflitto tra DPA e contratto principale prevale il
DPA per il trattamento dei dati personali.

## Allegato A — Dettagli del trattamento

| Voce | Valore |
|---|---|
| Categorie di interessati | Dipendenti, collaboratori, utenti degli endpoint, attaccanti esterni (Kraken) |
| Categorie di dati | Identificativi, telemetria endpoint, log, credenziali tentate, sample malware |
| Finalità | Sicurezza informatica, rilevamento e risposta agli incidenti |
| Retention | Telemetria 14 gg; alert 90 gg; audit 365 gg; syslog 30 gg; Kraken 30 gg/5 GiB; backup 7 gg |
| Localizzazione | [PAESE/DATA CENTER] |
| Sub-responsabili | [NESSUNO / ELENCO] |
| Misure ulteriori | [mTLS, isolamento Kraken, cifratura backup, accesso minimo] |

Firme:

Titolare ____________________  Data ________

Responsabile ________________  Data ________
