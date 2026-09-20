# Demo pulita — inizializzazione ambiente di test isolato (Fase 6)

Per non contaminare l'audit di produzione, ogni demo usa un **tenant di test**
(`is_test=true`) separato dal pilot.

## Tenant di test

- Tutti gli utenti creati dai test automatici (`pytest`, `scripts/e2e_*.py`)
  hanno username contenente `test` o `e2e` → `AuditLog.is_test = true`.
- L'endpoint `GET /audit/logs?exclude_test=true` nasconde i record di test;
  `include_test=true` (default) li mostra per debug.
- Gli eventi di telemetria e2e sono contrassegnati `agent_id` con prefisso
  test e filtrati via `fleet.py` site `test`.

## Inizializzare una demo pulita

```bash
# 1. Pulisci solo i dati di test (mai audit reali)
psql -h localhost -U postgres -d aegis -c "
  DELETE FROM incident_alerts WHERE alert_id IN (SELECT id FROM alerts WHERE agent_id IN (SELECT agent_id FROM agents WHERE hostname LIKE 'test-%'));
  DELETE FROM alerts WHERE agent_id IN (SELECT agent_id FROM agents WHERE hostname LIKE 'test-%');
  DELETE FROM telemetry WHERE device_id IN (SELECT agent_id FROM agents WHERE hostname LIKE 'test-%');
  DELETE FROM agents WHERE hostname LIKE 'test-%';
  UPDATE audit_logs SET is_test = true WHERE username ILIKE '%test%' OR username ILIKE '%e2e%';
"
# 2. Oppure ricrea da zero (solo lab, mai su pilot con dati reali)
./scripts/run_integration_tests.py --collect-only  # verifica -q
docker compose down -v
docker compose up -d --build
# 3. Verifica demo
curl -sk http://localhost:8000/api/v1/audit/logs?exclude_test=true | jq length
# deve restituire solo audit di produzione (0 su installazione pulita)
```

## Audit production immutabile

- `audit_logs` non ha `DELETE` via API (solo `GET`).
- La purge retention (`RETENTION_AUDIT_DAYS=365`) non cancella mai audit reali
  se `is_test=false` a meno di `confirm=true` + `backup_verified=true`.
- Backup cifrato (GPG) include audit + revoche.

## Tenant isolato in codice

- `app/core/audit.py:log_audit(is_test=...)` deduce automaticamente.
- `app/api/v1/audit.py` filtra via `is_test`.
- `conftest.py` imposta `AEGIS_TENANT=test` per i test.

## Limiti

- Senza `AEGIS_TENANT=test`, un evento manuale con username normale
  finisce in produzione. Per demo, crea sempre utenti con suffisso `test`.
