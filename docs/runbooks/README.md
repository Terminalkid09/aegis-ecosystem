# Runbook operativi Aegis 4.2

Questi runbook sono parte del gate di release: non sono note generiche, sono
le azioni che un operatore deve poter eseguire senza inventare comandi durante
un incidente. Ogni runbook indica cosa preservare, cosa isolare, come
verificare il ripristino e cosa registrare nell'audit.

| Runbook | Quando usarlo |
|---|---|
| [Agente compromesso](agent-compromised.md) | Un endpoint invia telemetria o comandi che non riconosci, oppure un secret device può essere stato letto. |
| [Brain compromesso](brain-compromised.md) | API, database, PKI o audit del piano di controllo sono sospetti. |
| [Kraken compromesso](kraken-compromised.md) | Honeypot, sandbox, broker o DB Kraken sono sospetti. |
| [Malware fuori sandbox](malware-escape.md) | Un campione o un comando è uscito dalla sandbox isolate. |
| [Backup e ripristino](backup-restore.md) | Backup fallito, corrotto, non verificato o ripristino richiesto. |

## Regole comuni

1. **Preserva prima di cancellare.** Copia log, audit, `docker inspect`, stato
   dei container e hash dei file su un supporto separato. La cancellazione
   distrugge la catena di evidenza.
2. **Non fare copia-incolla di secret nella chat o nei ticket.** Ruota i
   segreti coinvolti e registra solo l'identificatore della rotazione.
3. **Isola per rete, non solo per applicazione.** Un container compromesso può
   avere il socket Docker: fermare il processo non basta se il socket è ancora
   raggiungibile.
4. **Ogni azione va auditata.** Annota ora, operatore, comando, host,
   risultato e motivo. Se l'audit applicativo è compromesso, usa un registro
   esterno.
5. **Verifica il ripristino con un test, non con un'occhiata.** Un servizio
   che risponde 200 non prova che il DB sia integro: esegui il controllo di
   readiness, una query di conteggio e uno smoke di login/ingest.

## Contatti e autorità

- Incident commander: il responsabile SOC di turno.
- Autorità per revoca PKI e rotazione `JWT_SECRET`: amministratore della
  piattaforma.
- Autorità per eliminare dati o ripristinare un backup: proprietario del
  deployment, con conferma scritta.
- Per un sospetto malware: non allegare il campione ai ticket; conserva solo
  SHA-256 e posizione nel volume isolato.
