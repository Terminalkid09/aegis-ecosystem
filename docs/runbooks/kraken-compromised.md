# Runbook — compromised Kraken

**Objective:** contain a Kraken compromise without giving the attacker a pivot
into the Brain, the Aegis database or the host network.

Kraken is a separate microservice. The Brain must never become a command channel
for restoring it.

## 1. Isolation

1. stop `aegis-kraken-sensors`, `aegis-kraken` and `aegis-kraken-broker`;
2. disconnect the service from the `default` network and leave only the internal
   `kraken_internal` network for analysis, if possible;
3. revoke the SSO keys and Kraken's `INTERNAL_API_KEY`;
4. disable Kraken ingestion in the Brain (`KRAKEN_INGEST_ENABLED=false`) and
   rotate `KRAKEN_INGEST_SECRET`;
5. if the broker has the Docker socket, treat the Docker host as compromised:
   isolate the host, not just the container.

```bash
docker compose --profile kraken stop aegis-kraken aegis-kraken-sensors aegis-kraken-broker
docker compose --profile kraken logs --no-color aegis-kraken > evidence/kraken.log
```

## 2. Evidence

- dump of the Kraken DB and of the `kraken_data` volume;
- session logs, commands, credentials (already hashed) and samples with SHA-256;
- broker configuration and the Docker call allowlist;
- outbox events and their delivery status to the Brain;
- Caddy access logs for `/kraken/*`;
- hashes of the samples and decoy files, without copying malware into tickets.

## 3. Triage

- Did the attacker execute commands on the host through the broker?
- Did they obtain the Docker socket or the broker token?
- Did they read samples, credentials or GeoIP data?
- Did they alter sessions, campaigns, topologies or Lab runs?
- Did they use SSO to create an `aegis:*` user or steal a session?
- Did the outbox send fake events to the Brain? Compare `event_id` and HMAC.

## 4. Recovery

1. rebuild Kraken and the broker from clean images;
2. restore the DB and the volume from a verified backup, or start empty if
   integrity cannot be demonstrated;
3. rotate DB, Redis, `SECRET_KEY`, `INTERNAL_API_KEY`, SSO and ingest secrets;
4. re-enable ingestion only after verifying HMAC and the allowlist;
5. run a smoke test: sensor event → outbox → Brain event → Aegis view;
6. verify that the broker cannot create privileged containers.

## 5. Closure

Record which network was reachable, which samples were exposed, which secrets
were rotated and whether the Brain received unauthenticated events. Closure
includes a negative test: an event with a wrong HMAC must stay 401.
