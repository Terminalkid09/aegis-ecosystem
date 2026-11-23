# Deep simulation — Aegis/Kraken 4.3

Eseguita: `2026-11-23T17:31:25.281987+00:00` → `2026-11-23T17:44:16.055807+00:00`  
Stack: `http://127.0.0.1:8000` (Windows, pacchetti MSI 4.3.0, self-signed)  
Durata totale: **771s**

> Simulazione di comportamento, non esecuzione di malware. Ogni caso è
> inviato come evento reale al Brain con il flusso di enroll di un agente.
> Un agente dedicato per caso evita che la soppressione degli alert
> (per agente/regola/processo) falsi il conteggio.

## Detection

| Metrica | Valore |
|---|---:|
| Casi malevoli | 39 |
| Casi benigni | 46 |
| True positive | 38 |
| False negative | 1 |
| False positive | 0 |
| True negative | 46 |
| Precision | 1.000 |
| Recall | 0.974 |
| F1 | 0.987 |
| False positive rate | 0.000 |
| Severità corretta | 23/28 |

### Falsi negativi (comportamento non rilevato)

| Caso | Tecnica | Nota |
|---|---|---|
| `mal-linux-shadow` — lettura shadow | T1003.008 | T1003.008 non ha una regola statica: FN atteso |

### Severità diversa dall'atteso

| Caso | Attesa | Ottenuta |
|---|---|---|
| `mal-psh-encoded` | HIGH | CRITICAL |
| `mal-rundll32-js` | HIGH | LOW |
| `mal-threads` | MEDIUM | LOW |
| `mal-double-ext` | HIGH | CRITICAL |
| `mal-lolbin-temp` | HIGH | CRITICAL |

## Regole che hanno generato alert

| Regola | Alert |
|---|---:|
| AEGIS-S012 | 12 |
| AEGIS-S004 | 11 |
| AEGIS-S009 | 11 |
| AEGIS-S001 | 8 |
| AEGIS-S021 | 3 |
| AEGIS-S015 | 2 |
| AEGIS-S007 | 2 |
| AEGIS-S002 | 2 |
| AEGIS-S016 | 2 |
| AEGIS-S017 | 2 |
| AEGIS-S019 | 2 |
| AEGIS-S018 | 2 |
| AEGIS-S013 | 1 |
| AEGIS-S011 | 1 |
| AEGIS-S020 | 1 |
| AEGIS-S010 | 1 |
| AEGIS-S014 | 1 |
| AEGIS-S006 | 1 |

## Soak

| Metrica | Valore |
|---|---:|
| Agenti | 10 |
| Durata | 120.1s |
| Richieste | 16301 |
| Accettate | 16301 |
| Duplicati | 0 |
| Errori | 0 |
| Throughput | 135.69 rps |
| p50 / p95 / p99 | 70.6 / 101.4 / 124.9 ms |
| Eventi persi (server) | None |

## Controlli funzionali

| Controllo | Esito | Dettaglio |
|---|---|---|
| tutti i casi inviati con 200 | PASS | esempi=[] |
| heartbeat 200 | PASS | 200 |
| event_id duplicato riconosciuto | PASS | 200 status=duplicate |
| payload senza event_type rifiutato 422 | PASS | 422 |
| segreto agente errato rifiutato | PASS | 401 |
| command_line oltre il limite troncata, non 422 | PASS | 200 |
| 600 processi accettati (lista troncata, non 422) | PASS | 200 |
| lista processi troncata a 500 nel DB | PASS | righe=500 |
| NUL nella command line non rompe la scrittura | PASS | 200 |
| agente sconosciuto rifiutato | PASS | 401 |
| alert presente tra i non risolti | PASS |  |
| PATCH resolve 200 | PASS | {"id":585,"agent_id":"334e052f-b39a-4243-aa07-0472ed283292","agent_hostname":null,"timestamp":"2026-11-23T17:36:18.97130 |
| resolve riporta il muting attivo | PASS | triage_muted_seconds=604800 |
| resolve imposta is_resolved | PASS | True |
| risolto fuori dai non risolti | PASS |  |
| risolto presente nei risolti | PASS |  |
| dettaglio coerente con il resolve | PASS |  |
| detection identica silenziata dopo il resolve | PASS | 1->1 |
| riapertura alert 200 | PASS | {"id":585,"agent_id":"334e052f-b39a-4243-aa07-0472ed283292","agent_hostname":null,"timestamp":"2026-11-23T17:36:18.97130 |
| dopo la riapertura la detection torna visibile | PASS | 1->2 |
| resolve-all 200 | PASS | {"resolved":86,"triage_muted":86,"detail":"Resolved 86 alerts; similar detections muted ~7d for triaged patterns"} |
| resolve-all idempotente (seconda chiamata 0) | PASS | second=0 |
| viewer non puo' fare resolve-all (403) | PASS | 403 |
| viewer non puo' cancellare gli alert (403) | PASS | 403 |
| Kraken health 200 | PASS | 200 |
| Kraken ingest ssh 201 | PASS | 201 |
| Kraken ingest http 201 | PASS | 201 |
| Kraken ingest ftp 201 | PASS | 201 |
| Kraken ingest telnet 201 | PASS | 201 |
| Kraken ingest smb 201 | PASS | 201 |
| Kraken ingest rdp 201 | PASS | 201 |
| Kraken retry idempotente: nessuna seconda riga | PASS | status=201 rows=301->301 |
| Kraken rifiuta chiave interna errata | PASS | 403 |
| Aegis vede le sessioni deception Kraken | PASS | +6 |
| Aegis crea l'incidente Kraken | PASS | +6 |
| outbox Kraken consegnata | PASS | pending=0 |
| alert Kraken risolvibile dalla dashboard Aegis | PASS | {"id":600,"agent_id":"02c99b74-b95e-4b2a-8ac2-b68180df0d16","agent_hostname":null,"timestamp":"2026-11-23T17:40:17.88742 |
| nessuna password in chiaro negli incidenti Aegis | PASS | rows=0 |
| soak senza errori HTTP | PASS | errors=0 |
| soak senza eventi persi | PASS | lost=None |

## Limiti

- Eventi costruiti, non traffico reale né malware eseguito.
- La severità attesa è quella del contratto delle regole statiche 4.3.
- Il soak misura il percorso HTTP+DB su un singolo host; non è una
  capacità di flotta né una prova di scalabilità.
- Kraken è esercitato sul contratto sensori→app→Aegis; non è un
  test di esposizione honeypot su rete reale.
- La persistenza non è dedotta dal delta della tabella `telemetry`
  (tabella delle metriche, condivisa con altri agenti): è verificata
  dagli snapshot degli scenari e da probe diretti sull'agente.
