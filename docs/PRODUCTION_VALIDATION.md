# Production validation — soak, DR, HA and AP-126/127

Status: **the executable harness exists; the external evidence is still an
operator input.** This document separates what the repository can prove from
what only a real certificate, tenant, isolated lab, corpus and seven-day run
can prove.

## 7-day soak — what it is

A soak is a long-running, low-to-moderate synthetic workload. Ten or twenty
agents enroll, send heartbeats and report events continuously for seven days
while the runner samples readiness, the server's lost-event counter and the RSS
of the application containers. It is looking for a different class of defect
than a load test:

| Question | Short test | 7-day soak |
|---|---|---|
| Does the API work? | yes | yes |
| Does memory grow slowly? | usually invisible | measured across days |
| Do queues, retries or Redis keys accumulate? | usually invisible | visible in samples |
| Does a nightly job or log rotation break ingest? | no | yes |
| Does an agent reconnect after transient failures? | no | yes |
| Is an event silently lost? | one counter sample | continuous counter check |

It does **not** prove detection quality (AP-127), malware isolation (AP-126),
multi-host failover, or that a real attacker cannot evade a rule. A seven-day
soak is a duration requirement because leaks and slow backlogs are a function
of time, not request count.

Run it against a dedicated pilot stack, never production:

```bash
# AGENT_ENROLL_KEY in the environment or .env
python scripts/soak_7d.py --agents 20 --duration 7d \
  --base https://aegis.local --out-dir artifacts/soak-2026-11 \
  --containers aegis-brain,aegis-link --require-docker
```

The runner writes `soak-<tag>.jsonl` (one sample every five minutes) and
`soak-<tag>.json`. On Windows it holds `ES_SYSTEM_REQUIRED` so the workstation
does not sleep during the run. It fails on any enrollment/HTTP error, a
non-zero `aegis_events_lost_total` delta, a readiness failure, more than
`--max-rss-growth-mb` (default 128 MiB) of container growth, or a wall-clock gap
longer than two sample intervals. A laptop that suspends overnight has not
completed a continuous soak; use `--allow-gaps` only for debugging, never for
the release evidence. The random `soak-*` agents remain in the pilot database
as labelled test data; use a disposable database or clean them up with the
normal retention process.

A 7-day run cannot be shortened for a production claim. A 10-minute run is a
smoke test; it is useful in CI, but it is not the soak gate.

## Backup/restore drill

`scripts/test-restore.sh` already proves an encrypted PostgreSQL dump restores
into a disposable database. `scripts/dr_drill.sh` adds the PKI and artifact
bundle and writes evidence:

```bash
BACKUP_PASSPHRASE='...' ./scripts/dr_drill.sh
# PKI only (no psql):
./scripts/dr_drill.sh --skip-db
```

The drill never restores into the live database or live PKI volume. The PKI
part uses a harmless fixture to prove archive → GPG decrypt → extract; an
operator drill should set `PKI_SRC`/`ARTIFACTS_SRC` to a copy of the live
volumes and inspect the restored CA subject/dates. The real gate is a restore
of the operator's actual encrypted backup, followed by a service start and a
readiness check. The output is `dist/drills/dr-*.json`.

## HA and multi-host failure

The same-host HA overlay gives two Brain and two Link replicas. The guarded
drill kills one replica of each and requires readiness to recover:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
  -f docker-compose.ha.yml up -d --scale aegis-brain=2 --scale aegis-link=2
./scripts/ha_failure_drill.sh --yes
```

It records `postgres_failover: NOT_TESTED_SINGLE_HOST` and the same for Redis.
That is deliberate: `aegis-postgres` and `aegis-redis` are single instances in
Compose. A true multi-host failure test needs managed PostgreSQL with a replica
and Redis Sentinel/Cluster (or Patroni) and a second host; see `docs/HA.md`.
The script must not be reported as a multi-host pass.

When those services exist, use the external-trigger harness instead:

```bash
BRAIN_URLS=https://brain-a.example,https://brain-b.example \
PG_MEMBERS='postgresql://...@pg-a/aegis,postgresql://...@pg-b/aegis' \
REDIS_SENTINELS='sentinel-a:26379,sentinel-b:26379' \
  ./scripts/multi_host_failure_drill.sh --yes
# Trigger the managed failover in another terminal when prompted.
```

It observes a real PostgreSQL role change and/or Redis master change, requires
all Brain URLs to return ready, and fails if the lost-event counter increases.
It does not trigger the failover itself. If no external infrastructure is
provided, this gate is **not executed**, not passed.

## AP-126 — authorized detonation evidence

`scripts/test_sandbox_isolation.py` proves isolation with a harmless probe.
A real AP-126 result needs the operator's authorized sample, an isolated
VM/lab with a snapshot and verified restore, a kill switch, no public network,
and a process tree. `scripts/ap126_evidence.py` validates that evidence:

```bash
python scripts/ap126_evidence.py evidence.json --sample sample.bin --enforce
```

It rejects synthetic/incomplete evidence: missing snapshot restore, network
egress, no kill switch, expired authorization, wrong sample SHA-256. It does
not execute malware and cannot create the lab. Do not detonate malware on a
developer host or in the normal Docker Compose stack.

## AP-127 — real labelled corpus

`scripts/detection_quality_corpus.py` is the engine gate; it defaults to a
conservative 0.95 recall / 0.05 FPR. The missing input is a frozen, labelled
corpus with provenance, not another fixture. Run it against the operator's
corpus and retain the JSON with `corpus_sha256`:

```bash
PYTHONPATH=aegis-brain python scripts/detection_quality_corpus.py \
  real-corpus.jsonl --json-out dist/ap127.json --enforce
```

A synthetic corpus is an engine regression test only. It is not a production
detection-quality claim.

## Signing and MDM

Production Authenticode, GPG and cosign identities are operator secrets and are
not in this repository. The paths exist:

- `.github/workflows/packaging.yml` → `production_signing=true` uses the
  protected `production-signing` environment and fails if the PFX/GPG secrets
  are absent;
- `.github/workflows/ci.yml` signs `SHA256SUMS.txt` with cosign keyless OIDC on
  a tag;
- `docs/RELEASE_SIGNING.md` documents verification;
- `deploy/mdm/` contains Intune/GPO install, detect, uninstall and local
  validation scripts.

`deploy/mdm/Validate-Aegis.ps1` deliberately reports
`tenant_validation: "not_performed"`. A real Intune/GPO tenant must still prove
assignment, policy propagation and a clean-host lifecycle. The local scripts
reject a test-signed MSI and leave the service stopped when no token is
provided.

## Lab — what is and is not implemented

`deploy/kraken-lab/` starts three independent Kraken sensor containers and
`scripts/kraken_lab_multihost.py` probes each SSH/HTTP listener and writes
evidence. It is a **single-host simulation**: shared Docker engine/kernel, no
network partition, no source-IP preservation, no scheduler failover. The
evidence says `true_multi_host: false`. A real multi-host lab still needs
separate hosts and an orchestrator.

## Operator choices and external inputs

These are deliberate boundaries, not hidden defaults:

- **No secret is generated or stored by the repository.** A production
  Authenticode PFX, GPG key and cosign identity come from the operator; a local
  run without them is test-only.
- **No malware is executed on a developer host.** AP-126 needs a written
  authorization, an isolated VM/lab, a snapshot, a verified restore and a kill
  switch. `scripts/ap126_evidence.py` validates the evidence; it does not
  create the lab.
- **AP-127 needs a frozen labelled corpus with provenance.** A synthetic fixture
  is an engine regression test only. The output must retain `corpus_sha256`.
- **Soak agents are test records.** `soak-*` agents remain in the pilot
  database unless the operator uses a disposable database or removes them by
  the normal retention process.
- **The seven-day duration is not compressed.** A shorter run may be a smoke
  test, but it is not the production soak gate.
- **No automatic failover is triggered by the harness.** The multi-host drill
  waits for the operator's managed-service failover; without that external
  action it fails.
- **MDM scripts are optional wrappers around the MSI.** They require a real
  Intune/GPO tenant for assignment and policy evidence; the local validator
  reports `tenant_validation: "not_performed"`.

## Acceptance matrix

| Gate | Executable now | Still needs operator input |
|---|---|---|
| 7-day soak | `scripts/soak_7d.py` with sleep guard and gap detection | seven continuous real days on the pilot stack |
| Encrypted DB restore | `scripts/test-restore.sh` | real backup and retention policy |
| Encrypted DB+PKI drill | `scripts/dr_drill.sh` | live-volume copy and CA inspection |
| Same-host replica loss | `scripts/ha_failure_drill.sh` | HA overlay running |
| Multi-host PG/Redis failover | `scripts/multi_host_failure_drill.sh` | managed services, second host and external trigger |
| AP-126 | evidence validator | authorized sample and isolated lab |
| AP-127 | corpus runner | real labelled corpus |
| Production signatures | CI jobs | certificate/GPG/cosign identity |
| MDM/Intune/GPO | templates and local validation | real tenant and clean managed host |
| Multi-node Kraken lab | 3-container simulation | true separate hosts and network zones |

No row marked "still needs" is claimed as PASS by this repository.
