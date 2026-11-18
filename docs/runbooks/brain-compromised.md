# Runbook — Aegis Brain compromesso

**Obiettivo:** proteggere la PKI, i secret degli agenti, l'audit e il database
quando il piano di controllo è sospetto. Il Brain non deve essere raggiungibile
dagli agenti mentre viene analizzato.

## 1. Isolamento immediato

1. togli il Brain dal bilanciatore/Caddy e blocca le porte `8000` e `443`
   verso l'esterno;
2. ferma i worker outbox e i consumer Redis per evitare comandi o ingestione
   durante l'analisi;
3. revoca gli access token attivi e ruota `JWT_SECRET`;
4. ruota `AEGIS_API_KEY`, `AGENT_ENROLL_KEY` e i secret di integrazione;
5. non cancellare il container: esporta prima il filesystem, i log e il DB.

Comandi di contenimento (esempio Compose):

```bash
docker compose stop aegis-caddy aegis-brain
docker compose exec -T aegis-postgres pg_dump -U postgres aegis > evidence/aegis.sql
docker cp aegis-brain:/app/pki evidence/pki
```

Se il socket Docker è raggiungibile dal processo Brain, considera l'host
compromesso: non basta fermare il container.

## 2. Evidenza

- audit log completo, con hash e timestamp;
- `docker inspect` di Brain, Postgres e Redis;
- configurazione effettiva senza valori dei secret (`env` filtrato);
- dump DB e WAL, se disponibili;
- log di accesso Caddy e log applicativi;
- elenco dei certificati emessi e delle revoche.

Non copiare `MASTER_KEY_B64`, `JWT_SECRET` o chiavi private nei ticket.

## 3. Triage

- C'è stata una modifica di ruolo, una creazione utente o una revoca non
  autorizzata?
- Sono stati emessi certificati per agenti sconosciuti?
- Le regole Sigma o le soppressioni sono state alterate?
- Il database contiene tabelle o utenti nuovi?
- Un comando `script` o un'azione di remediation è stato eseguito fuori
  playbook?
- I backup sono integri e precedenti alla compromissione?

## 4. Ripristino

1. ricostruisci Brain e Caddy da immagine pulita e digest noto;
2. ripristina il DB da un backup verificato precedente alla compromissione;
3. ripristina la PKI solo se la CA non è stata esposta; altrimenti emetti una
   nuova CA e re-enrolla gli agenti;
4. ruota tutti i secret e invalida le sessioni;
5. verifica login, readiness, ingestione firmata e un alert di test;
6. riapri il traffico in modo graduale e monitora gli errori.

## 5. Chiusura

Registra l'intervallo di esposizione, i dati toccati, le revoche, il backup
usato e la verifica. Se la CA è stata compromessa, la chiusura include la
migrazione di tutti gli agenti alla nuova trust chain.
