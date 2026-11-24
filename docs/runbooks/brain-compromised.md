# Runbook — compromised Aegis Brain

**Objective:** protect the PKI, the agent secrets, the audit log and the
database when the control plane is suspect. The Brain must not be reachable by
agents while it is being analysed.

## 1. Immediate isolation

1. remove the Brain from the load balancer/Caddy and block ports `8000` and
   `443` towards the outside;
2. stop the outbox workers and the Redis consumers to prevent commands or
   ingestion during the analysis;
3. revoke active access tokens and rotate `JWT_SECRET`;
4. rotate `AEGIS_API_KEY`, `AGENT_ENROLL_KEY` and the integration secrets;
5. do not delete the container: export the filesystem, the logs and the DB
   first.

Containment commands (Compose example):

```bash
docker compose stop aegis-caddy aegis-brain
docker compose exec -T aegis-postgres pg_dump -U postgres aegis > evidence/aegis.sql
docker cp aegis-brain:/app/pki evidence/pki
```

If the Docker socket is reachable from the Brain process, treat the host as
compromised: stopping the container is not enough.

## 2. Evidence

- the complete audit log, with hashes and timestamps;
- `docker inspect` of Brain, Postgres and Redis;
- the effective configuration without secret values (filtered `env`);
- DB and WAL dumps, where available;
- Caddy access logs and application logs;
- the list of issued certificates and revocations.

Do not copy `MASTER_KEY_B64`, `JWT_SECRET` or private keys into tickets.

## 3. Triage

- Was there a role change, a user creation or an unauthorised revocation?
- Were certificates issued to unknown agents?
- Have the Sigma rules or the suppressions been altered?
- Does the database contain new tables or users?
- Was a `script` command or a remediation action executed outside a playbook?
- Are the backups intact and older than the compromise?

## 4. Recovery

1. rebuild Brain and Caddy from a clean image with a known digest;
2. restore the DB from a verified backup that predates the compromise;
3. restore the PKI only if the CA was not exposed; otherwise issue a new CA and
   re-enroll the agents;
4. rotate all secrets and invalidate the sessions;
5. verify login, readiness, signed ingestion and a test alert;
6. reopen traffic gradually and monitor for errors.

## 5. Closure

Record the exposure window, the data touched, the revocations, the backup used
and the verification. If the CA was compromised, closure includes migrating
every agent to the new trust chain.
