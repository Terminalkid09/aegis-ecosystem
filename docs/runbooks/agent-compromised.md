# Runbook — agente endpoint compromesso

**Obiettivo:** impedire che un `agent_id` compromesso riceva comandi,
inietti telemetria o venga usato per re-enrollare un altro host.

## 1. Conferma e contiene

1. annota `agent_id`, hostname, ultimo `last_seen`, versione e sito;
2. metti l'host in isolamento di rete dal firewall o dal playbook
   `isolate_host`, se disponibile;
3. revoca il certificato device e il device secret dall'interfaccia o dalla
   CLI amministrativa;
4. disabilita l'account locale o il servizio `AegisGuard` / `AegisNodeTrace`
   sull'host;
5. non riavviare l'agente finché non hai copiato i suoi log e il suo spool.

Comandi utili sul Brain:

```bash
docker exec aegis-brain python -m app.admin list
docker exec aegis-brain python -m app.admin set-role <email> analyst
```

La revoca PKI e la revoca dell'agente sono operazioni distinte: esegui
entrambe. La revoca dell'account non sostituisce quella del device.

## 2. Evidenza

Prima di cancellare l'host o il container, conserva:

- `journalctl -u AegisGuard` / `journalctl -u AegisNodeTrace` (Linux) o
  Event Viewer (Windows);
- `secret.json`, `token.json`, `device.crt` e lo spool locale, con hash e
  permessi, su un supporto cifrato;
- gli ultimi comandi ricevuti e gli ack dal DB/audit;
- l'elenco delle regole YARA e delle watchlist FIM inviate all'agente.

Non includere il device secret nei ticket. Se devi correlare un secret, usa
l'hash o l'ID della credenziale.

## 3. Analisi

- Cerca eventi di re-enroll per lo stesso hostname/os da IP diversi.
- Verifica se il token di enroll era monouso o statico.
- Confronta i comandi in coda con quelli attesi dal playbook.
- Controlla se l'agente ha inviato eventi con `event_id` duplicati o
  sequenze fuori ordine.
- Se il secret è finito in un log o in un crash dump, consideralo noto
  all'attaccante e ruota tutta la catena di enroll.

## 4. Ripristino

1. ricostruisci l'host da immagine pulita, non ripararlo in place;
2. installa l'agente con un token di enroll monouso e un nuovo device secret;
3. verifica che il vecchio `agent_id` non possa più autenticarsi;
4. esegui uno smoke di telemetria e un comando non distruttivo;
5. riapri l'host in rete solo dopo il triage.

## 5. Chiusura

Registra: causa, tempo di contenimento, comandi eseguiti, secret ruotati,
impatto sui dati e verifica del ripristino. Apri un follow-up se la revoca
richiede più di un'operazione manuale o se il vecchio agente continua a
comparire nella flotta.
