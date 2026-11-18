# Runbook — Kraken compromesso

**Obiettivo:** contenere un compromise di Kraken senza dare all'attaccante un
pivot verso il Brain, il database Aegis o la rete dell'host.

Kraken è un microservizio separato. Il Brain non deve mai diventare un canale
di comando per ripristinarlo.

## 1. Isolamento

1. ferma `aegis-kraken-sensors`, `aegis-kraken` e `aegis-kraken-broker`;
2. scollega il servizio dalla rete `default` e lascia solo la rete interna
   `kraken_internal` per l'analisi, se possible;
3. revoca le chiavi SSO e l'`INTERNAL_API_KEY` di Kraken;
4. disabilita l'ingest Kraken nel Brain (`KRAKEN_INGEST_ENABLED=false`) e
   ruota `KRAKEN_INGEST_SECRET`;
5. se il broker ha il socket Docker, considera l'host Docker compromesso:
   isola l'host, non solo il container.

```bash
docker compose --profile kraken stop aegis-kraken aegis-kraken-sensors aegis-kraken-broker
docker compose --profile kraken logs --no-color aegis-kraken > evidence/kraken.log
```

## 2. Evidenza

- dump del DB Kraken e del volume `kraken_data`;
- log di sessione, comandi, credenziali (già hash) e sample con SHA-256;
- configurazione del broker e allowlist delle chiamate Docker;
- eventi outbox e stato di consegna al Brain;
- access log di Caddy per `/kraken/*`;
- hash dei sample e dei file esca, senza copiare malware nei ticket.

## 3. Triage

- L'attaccante ha eseguito comandi sull'host tramite il broker?
- Ha ottenuto il socket Docker o il token del broker?
- Ha letto sample, credenziali o dati GeoIP?
- Ha alterato sessioni, campagne, topologie o run Lab?
- Ha usato l'SSO per creare un utente `aegis:*` o ha rubato una sessione?
- L'outbox ha inviato eventi falsi al Brain? Confronta `event_id` e HMAC.

## 4. Ripristino

1. ricostruisci Kraken e broker da immagini pulite;
2. ripristina il DB e il volume da un backup verificato, oppure riparti vuoto
   se l'integrità non è dimostrabile;
3. ruota DB, Redis, `SECRET_KEY`, `INTERNAL_API_KEY`, SSO e ingest secret;
4. riabilita l'ingest solo dopo aver verificato HMAC e allowlist;
5. esegui uno smoke: evento sensore → outbox → evento Brain → vista Aegis;
6. verifica che il broker non possa creare container privilegiati.

## 5. Chiusura

Registra quale rete era raggiungibile, quali sample sono stati esposti, quali
secret sono stati ruotati e se il Brain ha ricevuto eventi non autentici. La
chiusura include un test negativo: un evento con HMAC errato deve restare 401.
