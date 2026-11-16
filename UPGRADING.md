# Upgrading to Aegis Ecosystem 4.1.0

This is the upgrade guide for the **4.1.0 hardening minor**, the first
complete release after the batch tags.

## Before upgrading

1. Take an encrypted backup and verify its restore on a disposable database.
2. Export the current `.env` (or secret store) and compare it with the new
   `.env.example`.
3. Keep the previous image digests and the previous tag; rollback is described
   below.
4. Do not run the migration against a database you have not backed up.

## Changes that require action

### Aegis Brain

- The application now runs as the non-root user `aegis`. Existing named volumes
  `pki_data` and `artifact_data` created by root may need the one-time `chown`
  documented in `docs/OPERATIONS.md` §8.
- `AEGIS_PROFILE=prod` requires `MTLS_MODE=required`, `ENTERPRISE_STRICT=true`
  and a shared `RATE_LIMIT_STORAGE_URI`. A configuration that violated these
  rules before now fails at startup instead of running in a weaker mode.
- The removed `script` playbook action is rejected. Replace it with a named
  action before importing old playbooks.
- OTA requires an Ed25519-signed manifest. The legacy HMAC fallback is gone.
- Re-enrollment of an existing host requires a token issued for that hostname;
  the static enrollment key only creates new agents.

### Kraken (separate service, now in `services/kraken`)

- Kraken remains a separate process, database and network. It is **not** part of
  the Brain; the only channel is the signed `/api/v1/ingest/kraken` event.
- The application has no Docker socket. Sandboxes are created through the
  broker with `network_mode=none`, a read-only root filesystem, dropped
  capabilities and a bounded tmpfs.
- Set `AEGIS_INGEST_URL`, `AEGIS_INGEST_KEY` and `AEGIS_INGEST_SECRET` in the
  Kraken environment to enable event forwarding (disabled by default).
- Compose now fails if a required secret is missing. Copy the values into the
  external `.env` before starting; there are no default passwords.
- Backup requires `BACKUP_PASSPHRASE` and produces GPG-encrypted dumps with a
  checksum and a tested restore.
- Existing plaintext credential attempts must be removed by the migration;
  only HMAC values remain.

## Upgrade

```bash
git fetch --tags
git checkout v4.1.0
cp .env.example .env                 # merge, do not overwrite secrets
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
docker compose ps
curl -fsS https://aegis.local/health/ready
```

Alembic runs `upgrade head` at startup. If it fails, the container must not be
started with a partially migrated schema; restore the backup.

## Rollback

```bash
docker compose down
git checkout <previous-tag>
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

A schema downgrade is **not** automatic. If the previous release cannot read the
new schema, restore the pre-upgrade database backup first. Agent rollback uses
`POST /api/v1/deploy/update-command` with the previous version; artifacts are
versioned and never overwritten.

## Release verification

The bundle contains `RELEASE_MANIFEST.json`, `SHA256SUMS.txt`, the compose and
installer files, the Guard jar, NodeTrace/frontend archives, the source archive
and the SBOM. Verify before installing:

```bash
sha256sum -c SHA256SUMS.txt
python scripts/release-smoke.py release
```

The release job attaches the checksummed bundle. Cosign signing is a separate
step: verify `SHA256SUMS.txt.sig` when it is present, and do not describe a
bundle without it as a signed production artifact.
