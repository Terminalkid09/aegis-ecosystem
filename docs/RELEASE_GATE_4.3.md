# Aegis 4.3 — Release Gate

Status: 2026-11-19. **4.3 is still open; no `4.3.0` or `4.3.0-rc1` tag has
been cut.** The six gates below are part of the 4.3 release cycle, not a
post-4.3 cleanup. The cycle is deliberately longer: the product must have live
evidence before the tag, not only unit tests and documentation.

## Decision

**4.3.0 is a product-complete release candidate for controlled pilots, not a
certified malware-analysis release and not production GA.** The core paths are
implemented and tested, and the Link 50k queue boundary has live evidence. A
tag is allowed only after every item in the six-gate table is closed or
explicitly accepted as a recorded risk.

Real detonation, controlled malware samples and adversarial detection quality
remain in **4.3.x after the 4.3.0 tag** (AP-126/AP-127). The live stack,
delivery, upgrade/rollback and clean-install validation are **inside 4.3** and
must not be moved to that later track.

No new feature enters 4.3 while this gate is open. Firewall and DNS policy
belong to the 4.5 Network Visibility track, not to this release.

## Evidence

| Check | Evidence | Result |
|---|---|---|
| Link tests | `mvn -B test`, JDK 25, four test classes | **27 passed** |
| Link Redis-down path | controller tests: Redis exception → spool; Redis + spool down → 503, never a false 202 | **PASS** |
| Link 50k live cap | 50,001 HTTP events, 128 client workers, dedicated Redis with no consumer, spool disabled; 50,000 accepted, 1 × 429, `LLEN aegis:events = 50000`, 0 × 5xx, p95 160.1 ms | **PASS** |
| Brain command queue | `test_command_queue.py` on real Redis | **8 passed** |
| Brain restart | worker process claims and exits without ack; a second process recovers the same command after the lease, `delivery_attempt=2`, then acks | **PASS** |
| Release bundle local | `v4.3.0-rc1`, 22 files, manifest/checksums and smoke test from a copied bundle | **PASS (local)** |
| Brain concurrent cap | 20 producers, cap 5: 5 queued, 15 `queue_full` | **PASS** |
| Link command ack | claim, ack, duplicate ack, requeue without ack | **PASS** |
| Link live event | `POST /api/v1/events` → `202 accepted`; Redis queue/processing/DLQ `0/0/0`; row in `telemetry` | **PASS** |
| Go | `go test -count=1 ./...`; `--profile unified --check` | **PASS** |
| UI | `npm run build`; Playwright with Kraken seed | **13/13** |
| S3 adapter | Garage v2.5.0 upload/download/delete, two identical samples | **PASS** |
| Detection baseline | 14 malicious + 14 benign, synthetic | 14 TP, 0 FN, 5 FP, 9 TN |
| Diagrams | 4 draw.io sources + PNG/SVG, English, dark architecture system | **4/4** |

The 50k run is documented in `docs/benchmarks/4.3/link-load-50k.md`. It proves
the Link HTTP + Redis Lua boundary on one Docker Desktop host; it does not
prove a multi-host cluster, TLS throughput or 50,000 independent agent
processes.

## Six-gate release candidate (all inside 4.3)

This is the list to close before any push/tag intended as a release candidate.
**Gate 6 is the fundamental one: a clean install from the downloaded bundle
must pass before the release is pushed.**

| # | Gate | Status | Evidence / what remains |
|---|---|---|---|
| 1 | **AP-122** Link atomic check+push and 50k load | **PASS** | 50k live run above; keep the raw JSON with the release evidence |
| 2 | **AP-123** crash/restart and duplicate visibility | **PARTIAL** | Worker-process exit/restart and idempotent ack pass. The UI “queued ≠ executed” duplicate indication is still open |
| 3 | Release bundle from a clean download | **PARTIAL** | Local bundle from HEAD and smoke test from a copied bundle pass (22 files). A real GitHub download, signature/provenance and rollback assets are still unverified |
| 4 | Upgrade/rollback from 4.2.1 | **NOT RUN** | Windows and Linux: identity/spool migration, schema upgrade, restore, rollback to the previous tag |
| 5 | Hosted CI at the tag | **NOT RUN** | CI is tag/manual only. A local green run is not a hosted run; the `v4.3.0-rc1` tag workflow must be green |
| 6 | **Clean install from the downloaded bundle** | **NOT RUN** | Fresh machine/directory, no seeded data, install → enroll → live event → alert → uninstall, then repeat from the downloaded asset. **This is the gate before push** |

Do not cut `4.3.0-rc1` while gate 6 is unproven. Do not call the result a
release candidate merely because the local tests are green.

## Production gap after 4.3.0

This is the difference between a controlled-pilot release and production GA:

- signed MSI/deb/rpm packages and service drop-in, without `irm|iex` or
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

- a controlled-pilot release candidate with static analysis and optional
  external detonation integration;
- at-least-once command delivery, with possible duplicates after a crash;
- a verified 50k Link queue boundary on one host, with the exact numbers above;
- S3-compatible adapter tested with Garage; AWS optional and not certified;
- a frozen, synthetic detection baseline, not a production FP/FN rate.

## Not allowed

- “4.3.0 released” or “production GA” while the six-gate table is open;
- “real malware detonation certified”;
- “AWS tested” or “MinIO tested”;
- “exactly-once”;
- “production-ready detection quality”;
- “no data loss” without the process-kill test and restore drill.

## Release sequence

1. Freeze features.
2. Close gates 1–6, including the live 50k, restart, bundle, upgrade/rollback,
   hosted CI and clean-install evidence.
3. Tag `v4.3.0-rc1`; run the tag CI and the clean-download smoke test again.
4. Publish `v4.3.0` only after the RC evidence is reviewed and accepted.
5. Start AP-126/AP-127 live validation only after the 4.3.0 tag; no new
   firewall/DNS feature is part of 4.3.
