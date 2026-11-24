# Aegis 4.2 operations runbooks

These runbooks are part of the release gate: they are not generic notes, they
are the actions an operator must be able to perform without inventing commands
during an incident. Every runbook states what to preserve, what to isolate, how
to verify recovery and what to record in the audit log.

| Runbook | When to use it |
|---|---|
| [Compromised agent](agent-compromised.md) | An endpoint sends telemetry or commands you do not recognise, or a device secret may have been read. |
| [Compromised Brain](brain-compromised.md) | The API, database, PKI or control-plane audit log is suspect. |
| [Compromised Kraken](kraken-compromised.md) | The honeypot, sandbox, broker or Kraken DB is suspect. |
| [Malware outside the sandbox](malware-escape.md) | A sample or command has left the isolated sandbox. |
| [Backup and restore](backup-restore.md) | A backup failed, is corrupt, is unverified or a restore is required. |

## Common rules

1. **Preserve before deleting.** Copy logs, audit records, `docker inspect`,
   container state and file hashes to separate media. Deletion destroys the
   chain of evidence.
2. **Never copy-paste secrets into chat or tickets.** Rotate the affected
   secrets and record only the rotation identifier.
3. **Isolate by network, not only by application.** A compromised container may
   have the Docker socket: stopping the process is not enough if the socket is
   still reachable.
4. **Every action must be audited.** Note the time, operator, command, host,
   result and reason. If the application audit log is compromised, use an
   external register.
5. **Verify recovery with a test, not with a glance.** A service that answers
   200 does not prove the DB is intact: run the readiness check, a count query
   and a login/ingest smoke test.

## Contacts and authorities

- Incident commander: the SOC lead on duty.
- Authority for PKI revocation and `JWT_SECRET` rotation: the platform
  administrator.
- Authority to delete data or restore a backup: the deployment owner, with
  written confirmation.
- For suspected malware: do not attach the sample to tickets; keep only the
  SHA-256 and its location in the isolated volume.
