# Runbook — backup and restore

**Objective:** demonstrate that a backup is intact and restorable, not just that
the job exited 0.

## 1. Periodic verification

1. the backup job must produce a file with a checksum and a timestamp;
2. the checksum must be verified on the file just written, not only at the end
   of the month;
3. run a restore on a disposable database whose name contains `test`;
4. compare the main tables and counts (users, agents, events, audit);
5. record the result with date, duration and size.

```bash
sha256sum -c backup.sha256
pg_restore --clean --if-exists --no-owner -d "$TEST_DATABASE_URL" backup.dump
```

Do not restore onto a production database "to try it". The DB name must contain
`test` and the connection must be separate.

## 2. Failed backup

1. do not delete the previous backup;
2. check space, permissions, credentials and DB locks;
3. verify that the passphrase is not in a world-readable file;
4. re-run into a temporary path and verify the checksum;
5. if the failure is recurring, open an incident: an unverified backup is the
   same as no backup.

## 3. Emergency restore

1. declare the window and stop the consumers/workers;
2. save the current DB, even if corrupt, for analysis;
3. restore the chosen backup onto a new DB;
4. run migrations only if the backup predates the current schema;
5. start the Brain against the new DB and verify `/health/ready`;
6. run a login, an audit query and an ingestion smoke test;
7. reopen traffic and monitor errors and lag.

## 4. After the restore

- rotate credentials if the backup contained secrets or the environment is
  suspect;
- verify that agents did not duplicate events or commands during the window;
- compare the expected number of events and alerts with the restored ones;
- record the restore point (timestamp and checksum) in the audit log.

## 5. Closure criterion

A restore is closed only when an automated test has verified the checksum, the
counts, readiness and an end-to-end smoke test. A backup without a proven
restore is not a backup: it is only a file.
