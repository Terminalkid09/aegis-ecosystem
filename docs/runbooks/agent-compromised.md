# Runbook — compromised endpoint agent

**Objective:** prevent a compromised `agent_id` from receiving commands,
injecting telemetry or being used to re-enroll another host.

## 1. Confirm and contain

1. record the `agent_id`, hostname, last `last_seen`, version and site;
2. put the host into network isolation through the firewall or the
   `isolate_host` playbook, if available;
3. revoke the device certificate and the device secret from the UI or the
   administrative CLI;
4. disable the local account or the `AegisGuard` / `AegisNodeTrace` service on
   the host;
5. do not restart the agent until you have copied its logs and its spool.

Useful commands on the Brain:

```bash
docker exec aegis-brain python -m app.admin list
docker exec aegis-brain python -m app.admin set-role <email> analyst
```

PKI revocation and agent revocation are separate operations: perform both.
Revoking the account does not replace revoking the device.

## 2. Evidence

Before deleting the host or the container, preserve:

- `journalctl -u AegisGuard` / `journalctl -u AegisNodeTrace` (Linux) or Event
  Viewer (Windows);
- `secret.json`, `token.json`, `device.crt` and the local spool, with hashes and
  permissions, on encrypted media;
- the last commands received and the acks from the DB/audit log;
- the list of YARA rules and FIM watchlists sent to the agent.

Do not include the device secret in tickets. If you must correlate a secret,
use its hash or the credential ID.

## 3. Analysis

- Look for re-enrollment events for the same hostname/OS from different IPs.
- Check whether the enrollment token was single-use or static.
- Compare the queued commands with the ones expected from the playbook.
- Check whether the agent sent events with duplicate `event_id` values or
  out-of-order sequences.
- If the secret leaked into a log or a crash dump, treat it as known to the
  attacker and rotate the whole enrollment chain.

## 4. Recovery

1. rebuild the host from a clean image, do not repair it in place;
2. install the agent with a single-use enrollment token and a new device
   secret;
3. verify that the old `agent_id` can no longer authenticate;
4. run a telemetry smoke test and a non-destructive command;
5. only put the host back on the network after triage.

## 5. Closure

Record: cause, containment time, commands executed, rotated secrets, data
impact and recovery verification. Open a follow-up if revocation requires more
than one manual operation or if the old agent keeps appearing in the fleet.
