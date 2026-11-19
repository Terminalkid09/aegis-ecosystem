# Aegis 4.3 — Release Gate

Status: 2026-11-19. **No `v4.3.0` tag has been cut and nothing is published.**
The five locally executable gates are green; the hosted-CI gate requires the
tag push and is the only remaining release action. There is no `4.3.0-rc1`:
the release is cut directly as `v4.3.0`.

## Decision

**4.3.0 is a product-complete controlled-pilot release, not a certified
malware-analysis release and not production GA.** The live install, enrollment,
event, detection, upgrade, bundle and clean-install paths have real evidence.
The tag may be created only after the hosted tag workflow is green.

Agent rollback is explicitly **out of scope** for 4.3.0: there is no requirement
to roll back to the previous Guard/NodeTrace agents. The supported rollback
boundary is the server plus database restore. Firewall and DNS policy remain in
the 4.5 Network Visibility track.

## Local evidence

| Check | Evidence | Result |
|---|---|---|
| Link tests | `mvn -B test`, JDK 25, four test classes | **27 passed** |
| Link Redis-down path | Redis exception → spool; Redis + spool down → 503, never a false 202 | **PASS** |
| Link 50k live cap | 50,001 HTTP events, 128 client workers, dedicated Redis with no consumer, spool disabled; 50,000 accepted, 1 × 429, `LLEN aegis:events = 50000`, 0 × 5xx, p95 160.1 ms | **PASS** |
| Brain command queue | `test_command_queue.py` on real Redis | **8 passed** |
| Brain restart | worker process claims and exits without ack; a second process recovers the same command after the lease, `delivery_attempt=2`, then acks | **PASS** |
| Command duplicate visibility | OTA panel reports `queued — not executed`, requires an agent ack and states that a crash before the ack can replay the command once; frontend production build passes | **PASS** |
| Server upgrade | dump of the running 4.2.1 database (68 agents, 321 alerts, Alembic `0022`) restored into a fresh project; Brain 4.3.0 starts at `0022 (head)`; API smoke | **PASS, 21/21** |
| Bundle | `v4.3.0`, 22 files, manifest + `SHA256SUMS`, smoke from a copied bundle | **PASS (local)** |
| Clean install from bundle | source archive extracted from the bundle, new project/volumes/ports, image build, admin bootstrap, enrollment, heartbeat, agent event, alert Sigma `T1110.001`; frontend 200, Link UP, API smoke | **PASS, 21/21** |
| Clean install from Git clone | local clone of `31962cd` with no build outputs, new project/volumes; same install/enroll/event/alert/smoke path | **PASS, 21/21** |
| Version surfaces | Brain `/health/live`, frontend build, Guard POM, NodeTrace, Go agent | `4.3.0` |
| Go | `go test -count=1 ./...`; `--profile unified --check` | **PASS** |
| UI | `npm run build`; Playwright with Kraken seed | **13/13** |
| S3 adapter | Garage v2.5.0 upload/download/delete, two identical samples | **PASS** |
| Detection baseline | 14 malicious + 14 benign, synthetic | 14 TP, 0 FN, 5 FP, 9 TN |
| Diagrams | 4 draw.io sources + PNG/SVG, English, dark architecture system, version `4.3.0` | **4/4** |

The 50k run is documented in `docs/benchmarks/4.3/link-load-50k.md`. It proves
the Link HTTP + Redis Lua boundary on one Docker Desktop host; it does not
prove a multi-host cluster, TLS throughput or 50,000 independent agent
processes. The clean-install test proves the Compose/API path, not the native
Windows/Linux agent service packaging.

## Six gates

| # | Gate | Status | Evidence / what remains |
|---|---|---|---|
| 1 | **AP-122** Link atomic check+push and 50k load | **PASS** | 50k live run above; raw evidence retained |
| 2 | **AP-123** crash/restart and duplicate visibility | **PASS** | process restart/`attempt=2` and idempotent ack pass; OTA UI says `queued — not executed` and explains the ack/replay boundary |
| 3 | Release bundle from a clean download | **PASS (local)** | 22-file `v4.3.0` bundle; manifest/checksums and copied-bundle smoke pass. GitHub asset download, cosign/provenance verification remain tag-time work; the release is unsigned by decision (`docs/RELEASE_SIGNING.md`) |
| 4 | Upgrade from 4.2.1 | **PASS (server-only)** | 4.2.1 DB restored, 68 agents/321 alerts preserved, Brain 4.3.0 at Alembic head, smoke 21/21. Agent rollback is out of scope by decision |
| 5 | Hosted CI at the tag | **NOT RUN** | CI is tag/manual only. The `v4.3.0` tag workflow must be green before publishing; a local green run is not a substitute |
| 6 | **Clean install from the release bundle** | **PASS** | source archive extracted from `v4.3.0`, empty volumes, build + bootstrap + enrollment + event + alert + frontend/Link + smoke 21/21 |

**Gate 5 is the only remaining release blocker.** Do not publish the tag or
call 4.3.0 released until that hosted run is green and its artifacts are
verified.

## Production gap after 4.3.0

This is the difference between a controlled-pilot release and production GA:

- signed MSI/deb/rpm packages and native service drop-in, without `irm|iex` or
  `curl|bash` as the production path;
- 7-day soak with memory/leak checks, restart and duplicate-action visibility;
- real endpoint traffic and a real malware corpus (AP-126);
- measured detection quality on real benign/malicious data (AP-127);
- external security review/pen test and a backup/restore drill;
- multi-host Redis/Postgres failure tests and a documented support model.

Real detonation and AWS are **not** blockers for 4.3.0:

- real detonation: AP-126, after the 4.3.0 tag;
- AWS/MinIO: optional by design; Garage and local storage are supported for
  the pilot. AWS is not certified.

## Allowed claims

- a controlled-pilot release with static analysis and optional external
  detonation integration;
- at-least-once command delivery, with possible duplicates after a crash;
- a verified 50k Link queue boundary on one host, with the exact numbers above;
- S3-compatible adapter tested with Garage; AWS optional and not certified;
- a frozen, synthetic detection baseline, not a production FP/FN rate;
- server upgrade from 4.2.1 with the database data preserved.

## Not allowed

- “4.3.0 released” or “production GA” while gate 5 is not green;
- “real malware detonation certified”;
- “AWS tested” or “MinIO tested”;
- “exactly-once”;
- “production-ready detection quality”;
- “agent rollback tested” (it is outside 4.3.0);
- “no data loss” without the process-kill test and restore drill.

## Release sequence

1. Commit the release state on `feat/4.3-agent-go`.
2. Create the annotated `v4.3.0` tag and push it only as the release action.
3. Run the tag workflow; require gate 5 green and verify the downloaded assets
   and provenance attestation.
4. Publish `v4.3.0`; do not create `4.3.0-rc1`.
5. Start AP-126/AP-127 live validation only after the 4.3.0 tag; no new
   firewall/DNS feature is part of 4.3.
