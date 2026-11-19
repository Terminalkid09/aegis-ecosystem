# Aegis — Live Validation Roadmap (post-4.3)

Status: decision record, 2026-11-19. This document is the English source of
truth for the validation work that is kept **inside the 4.3.0 release cycle**.
The older Italian `docs/ROADMAP.md` remains the long-term product roadmap;
this file defines the release boundary that matters now. AP-126/AP-127 start
only after the 4.3.0 tag; they are not part of the RC gate.

## Decision

- **4.3.0** will ship as a product-complete release candidate for controlled
  pilots after the six RC gates pass: static analysis, optional external
  detonation integration, local/Garage object storage and the at-least-once
  command path. No tag exists yet.
- The six gates (50k Link load, crash/restart, release bundle, 4.2.1
  upgrade/rollback, hosted CI at tag and clean install) are part of 4.3, not a
  post-release cleanup. The 4.3 cycle is intentionally longer to collect live
  evidence before the tag.
- **4.3.0 does not claim certified real-malware detonation.** The integration
  is exercised with a controlled HTTP detonator; no malware is executed on the
  host or by the web process.
- Real detonation, controlled malware samples and adversarial quality work are
  a **post-4.3 live-validation track**. They must not be presented as already
  delivered.
- **AWS is optional.** A customer may run local storage, Garage/Ceph on their
  own server, or AWS S3. A home user can stay local or on a router; an
  enterprise can self-host. No cloud dependency is required for 4.3.
- CI is executed at the release/tag boundary, not on every intermediate state.
  Pushing is reserved for a release candidate or an explicit saved state.

## Phase 1 — 4.3.0-rc1 (inside 4.3)

**Goal:** a coherent, honest controlled-pilot release candidate with live
evidence before the tag.

Required evidence:

- Link HTTP → Redis → Brain → Postgres live path;
- atomic Link check+push, no `202` when neither Redis nor spool accepted;
- Link 50k boundary: 50,000 accepted, one 429, Redis depth at the cap, no 5xx;
- command claim/ack/requeue/DLQ on Brain and Link;
- restart after a claim without ack, with the same `delivery_id` and attempt 2;
- UI / Playwright and Go tests green;
- static file analysis, job recovery, deletion verification;
- optional S3 adapter tested against an S3-compatible server;
- release bundle smoke test, upgrade/rollback, hosted CI at tag and clean
  install (the six gates in `docs/RELEASE_GATE_4.3.md`);
- diagrams and docs in English for the public-facing material.

Out of scope for the 4.3.0 claim:

- real malware execution (AP-126, after the tag);
- certified sandbox isolation;
- AWS certification;
- production FP/FN rates (AP-127, after the tag).
- firewall and DNS policy features (4.5 Network Visibility).

## Phase 2 — 4.3.x live validation (after 4.3.0)

**Goal:** test the paths that only a real lab can validate. This phase starts
after the 4.3.0 tag; it is not a substitute for the six RC gates above.

1. **Real detonation worker** (AP-126)
   - isolated Windows/Linux VM or container, no Internet, snapshot/restore;
   - CAPE/Cuckoo or an equivalent controlled sandbox;
   - authorized sample only;
   - process tree, DNS history, timeout, kill switch, teardown;
   - report must say `real` vs `static-only` explicitly.
2. **Detection quality** (AP-127)
   - freeze the 4.3 synthetic set;
   - add a benign corpus of legitimate admin tools with unusual arguments;
   - measure FP/FN, per-host/day, severity and analyst load;
   - improve prevalence/allowlist/confidence without hiding regressions.
3. **Incident and queue tests**
   - Brain unavailable, Redis down, restart, visibility timeout;
   - crash between execution and ack;
   - duplicate action visibility in UI.
4. **Operational packaging**
   - backup/restore, retention, deletion proof;
   - release download and smoke test from a clean machine.

## Phase 3 — 4.4

Only after the live-validation evidence is acceptable:

- response intelligence and approval gates;
- real detonation as a supported, documented integration;
- detection rules driven by measured false positives, not by demos;
- optional S3/AWS production policy templates (retention, immutability,
  private bucket, IAM least privilege).

## Phase 4 — 5.0

5.0 remains a measured decision, not a reward for finishing 4.3:

- 500 agents / 2,000 ev/s sustained;
- Kafka/Redpanda only beyond 50,000 ev/s, 20 independent consumer groups or
  historical replay > 7 days;
- Kubernetes/Helm only beyond 5 nodes or real autoscaling/multi-tenant needs;
- multi-tenancy only for MSSP with isolation and restore tests.

## Honest claims

Allowed for 4.3.0:

- “static analysis and optional external detonation integration”;
- “at-least-once command delivery, duplicates possible”;
- “S3-compatible adapter, tested with Garage; AWS optional and not certified”;
- “synthetic detection baseline, not a production FP/FN rate”.

Not allowed:

- “real malware detonation certified”;
- “AWS tested” or “MinIO tested”;
- “exactly-once”;
- “production-ready detection quality”.

## References

- `docs/RELEASE_GATE_4.3.md`
- `docs/benchmarks/4.3/detection-quality.md`
- `docs/ARCHITECTURE_AEGIS_KRAKEN.md`
- AP-126, AP-127 in YouTrack
