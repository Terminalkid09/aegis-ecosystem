# Upgrading to Aegis Ecosystem 4.3.0

This is the upgrade guide for the **4.3.0 release**. There is no `4.3.0-rc1`
tag and no separate release-candidate cut: the release is cut directly as
`v4.3.0` after the live gates are green.

The 4.3.0 release ships **only** the unified Go agent runtime for controlled
pilots. Guard Java and NodeTrace Python remain in the source tree for 4.2.1
compatibility, but they are not in the 4.3 bundle and are not offered by the
4.3 deployment UI. Rolling back those legacy agents is **not** part of 4.3.0;
the supported rollback boundary is the server stack.

## Before upgrading

1. Take an encrypted backup and verify its restore on a disposable database.
2. Export the current `.env` (or secret store) and compare it with the new
   `.env.example`.
3. Keep the previous image digests and the previous tag.
4. Do not run the migration against a database you have not backed up.

## Changes that require action

### Brain and database

- Brain reports version `4.3.0` and applies every pending Alembic revision on
  startup.
- The server upgrade path was exercised from the running 4.2.1 database into a
  fresh 4.3.0 project; the database dump is restored before the new Brain
  starts. A schema downgrade is not automatic.
- `AEGIS_PROFILE=prod` still requires `MTLS_MODE=required`,
  `ENTERPRISE_STRICT=true` and a shared `RATE_LIMIT_STORAGE_URI`.
- The legacy `X-Client-Cert` header is rejected; use
  `X-Client-Cert-Hash`.
- Re-enrollment of an existing host requires a host-bound token.

### Agents

- The Go agent reports `agent_version=4.3.0` and supports the `sensor`,
  `endpoint` and `unified` profiles.
- Existing Guard and NodeTrace installations keep running against the 4.3
  Brain, but the 4.3 bundle no longer contains their artifacts. A host that
  must be reinstalled or upgraded moves to the unified agent; there is no
  artifact-level fallback in this bundle.
- This release does **not** require or test rollback to the previous Java or
  Python agent. Do not promise that rollback in a pilot.

### Link and command delivery

- Link keeps the durable spool, atomic check+push, visibility timeout and
  idempotent ack.
- Command delivery is **at-least-once**. A crash after execution and before
  the ack can replay the same command. The UI now says `queued — not executed`
  and requires an agent ack before treating the action as run.
- The 50k Link boundary is a tested single-host limit, not a cluster claim.

## Upgrade

```bash
git fetch --tags
git checkout v4.3.0
cp .env.example .env  # merge; do not overwrite existing secrets
docker compose build aegis-brain aegis-link aegis-frontend
docker compose up -d
docker compose ps
curl -fsS https://aegis.local/health/ready
```

For a clean install in an isolated project, use new Docker project names and
new volumes. Do not reuse a 4.2.1 data volume without a verified backup.

## Rollback

```bash
# Server-only rollback: restore the pre-upgrade database first, then start the
# previous server tag. Agent rollback is outside the 4.3.0 scope.
docker compose down
git checkout <previous-tag>
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

If the previous release cannot read the new schema, restore the database
backup. Never run an older Brain against a newer schema without that restore.

## Release verification

Verify the downloaded bundle before installing:

```bash
sha256sum -c SHA256SUMS.txt
python scripts/release-smoke.py release --require-agent --require-image-sboms
```

The bundle ships `env.example` rather than `.env.example`: GitHub rewrites
asset names that begin with a dot. The installers accept either name.

The 4.3.0 bundle ships only the unified agent: `unified-latest.zip` on Windows
and `unified-latest.tar.gz` on Linux, plus the versioned `unified-4.3.0.*` OTA
copies. The Windows archive contains `aegis-agent.exe` and `aegis-etw.exe`; the
Linux archive contains `aegis-agent`, `aegis-collector` and
`aegis_exec.bpf.o`. Guard/NodeTrace artifacts are not present.

Cosign signing is a separate step. `v4.3.0` is checksummed and carries a
build-provenance attestation, but it is **not** described as a signed
production artifact. See `docs/RELEASE_SIGNING.md`.
