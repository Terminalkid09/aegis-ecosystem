# Runbook — backup e ripristino

**Obiettivo:** dimostrare che un backup è integro e ripristinabile, non solo
che il job è terminato con exit 0.

## 1. Verifica periodica

1. il job di backup deve produrre un file con checksum e timestamp;
2. il checksum va verificato sul file appena scritto, non solo a fine mese;
3. esegui un restore su un database usa-e-getta con nome che contiene
   `test`;
4. confronta tabelle e conteggi principali (utenti, agenti, eventi, audit);
5. registra l'esito con data, durata e dimensione.

```bash
sha256sum -c backup.sha256
pg_restore --clean --if-exists --no-owner -d "$TEST_DATABASE_URL" backup.dump
```

Non ripristinare su un database di produzione per "provare". Il nome del DB
deve contenere `test` e la connessione deve essere separata.

## 2. Backup fallito

1. non cancellare il backup precedente;
2. controlla spazio, permessi, credenziali e lock del DB;
3. verifica che la passphrase non sia in un file leggibile da altri;
4. riesegui in un percorso temporaneo e verifica il checksum;
5. se il fallimento è ricorrente, apri un incidente: un backup non
   verificato equivale a nessun backup.

## 3. Ripristino di emergenza

1. dichiara la finestra e ferma i consumer/worker;
2. salva il DB corrente, anche se corrotto, per l'analisi;
3. ripristina il backup scelto su un DB nuovo;
4. esegui le migrazioni solo se il backup è precedente allo schema corrente;
5. avvia Brain con il DB nuovo e verifica `/health/ready`;
6. esegui login, una query di audit e uno smoke di ingestione;
7. riapri il traffico e monitora errori e lag.

## 4. Dopo il ripristino

- ruota le credenziali se il backup conteneva secret o se l'ambiente è
  sospetto;
- verifica che gli agenti non abbiano duplicato eventi o comandi durante la
  finestra;
- confronta il numero di eventi e alert attesi con quelli ripristinati;
- annota il punto di ripristino (timestamp e checksum) nell'audit.

## 5. Criterio di chiusura

Il ripristino è chiuso solo quando un test automatico ha verificato checksum,
conteggi, readiness e uno smoke end-to-end. Un backup senza restore provato
non è un backup: è solo un file.
