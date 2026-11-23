# Clean demo — isolated test environment setup (Phase 6)

To avoid contaminating the production audit, every demo uses a separate
**test tenant** (`is_test=true`).

## Test tenant

- Every user created by automated tests (`pytest`, `scripts/e2e_*.py`) has a
  username containing `test` or `e2e` → `AuditLog.is_test = true`.
- `GET /audit/logs?exclude_test=true` hides test records; `include_test=true`
  (default) shows them for debugging.
- E2E telemetry events use an `agent_id` with a test prefix and are filtered by
  `fleet.py` site `test`.

## Initialize a clean demo

```bash
# 1. Delete test data only (never real audit records)
psql -h localhost -U postgres -d aegis -c "
  DELETE FROM incident_alerts WHERE alert_id IN (SELECT id FROM alerts WHERE agent_id IN (SELECT agent_id FROM agents WHERE hostname LIKE 'test-%'));
  DELETE FROM alerts WHERE agent_id IN (SELECT agent_id FROM agents WHERE hostname LIKE 'test-%');
  DELETE FROM telemetry WHERE device_id IN (SELECT agent_id FROM agents WHERE hostname LIKE 'test-%');
  DELETE FROM agents WHERE hostname LIKE 'test-%';
  UPDATE audit_logs SET is_test = true WHERE username ILIKE '%test%' OR username ILIKE '%e2e%';
"
# 2. Or rebuild from scratch (lab only, never on a pilot with real data)
./scripts/run_integration_tests.py --collect-only  # verify -q
docker compose down -v
docker compose up -d --build
# 3. Verify the demo
curl -sk http://localhost:8000/api/v1/audit/logs?exclude_test=true | jq length
# must return only production audit records (0 on a clean install)
```

## Immutable production audit

- `audit_logs` has no API `DELETE` (read-only `GET`).
- Retention purge (`RETENTION_AUDIT_DAYS=365`) never deletes real audit records
  when `is_test=false` unless `confirm=true` and `backup_verified=true`.
- The encrypted GPG backup includes audit records and revocations.

## Tenant isolation in code

- `app/core/audit.py:log_audit(is_test=...)` infers the flag automatically.
- `app/api/v1/audit.py` filters by `is_test`.
- `conftest.py` sets `AEGIS_TENANT=test` for tests.

## Limits

- Without `AEGIS_TENANT=test`, a manual event with a normal username is written
  to production. For a demo, always create users with a `test` suffix.
