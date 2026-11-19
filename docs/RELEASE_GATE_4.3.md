# Aegis 4.3 — Release Gate

Status: 2026-11-19. This gate defines what 4.3.0 may claim.

## Decision

**4.3.0 is a lab-validated product release, not a certified malware-analysis
release.** It can be tagged after the final packaging gate. It must not claim
real-malware detonation, AWS certification, or production FP/FN rates.

Real detonation, controlled malware samples and adversarial detection quality
are tracked in the **post-4.3 live-validation roadmap**:
`docs/ROADMAP_LIVE_VALIDATION.md` (AP-126/AP-127).

## Evidence

| Check | Evidence | Result |
|---|---|---|
| Link tests | `mvn -B -q test`, JDK 25 | 25 passed |
| Link live event | `POST /api/v1/events` → `202 accepted`; Redis queue/processing/DLQ `0/0/0`; row in `telemetry` | PASS |
| Link command ack | claim, ack, duplicate ack, requeue without ack | PASS |
| Link atomic push | check+push in one Lua script; 202 only after `LPUSH` or spool | implemented |
| Brain command queue | `test_command_queue.py` on real Redis, 6 tests | 6 passed |
| Brain concurrent cap | 20 producers, cap 5: 5 queued, 15 `queue_full` | PASS |
| Go | `go test -count=1 ./...`; `--profile unified --check` | PASS |
| UI | `npm run build`; Playwright with Kraken seed | 13/13 |
| S3 adapter | Garage v2.5.0 upload/download/delete, two identical samples | PASS |
| Detection baseline | 14 malicious + 14 benign, synthetic | 14 TP, 0 FN, 5 FP, 9 TN |
| Diagrams | 4 draw.io sources + PNG/SVG, English | 4/4 |

The 4.3 baseline is **synthetic**: precision `0.737`, recall `1.000`, F1
`0.848`, FPR `0.357`; thread threshold is 201, not 200. It is not a production
rate. AP-127 covers the next quality iteration.

## Open items before the tag

These are packaging/verification items, not new features:

1. **Hosted CI at the tag.** Run the E2E/release job only when preparing the
   tag; do not push an intermediate state just to test CI.
2. **Release assets from a clean download.** Verify checksums, SBOM, installer
   and rollback.
3. **AP-123 crash/UI check.** The command queue is at-least-once; verify the
   “queued ≠ executed” semantics and a real process restart.
4. **AP-122 cap load test.** The atomic script is implemented and the live
   event path passes; a 50k concurrent-producer test is still a useful
   acceptance test, not a reason to block the code review.
5. **Link event path** is now green; no longer a blocker.

Real detonation and AWS are **not** blockers for 4.3.0:

- real detonation: AP-126, post-4.3;
- AWS/MinIO: optional by design, not part of AP-127. A customer may
  self-host Garage/Ceph, keep local storage, or use AWS S3.

## Allowed claims for 4.3.0

- static file analysis and **optional external detonation integration**;
- at-least-once command delivery, with possible duplicates after a crash;
- S3-compatible adapter tested with Garage; AWS optional and not certified;
- a frozen, synthetic detection baseline, not a production FP/FN rate.

## Not allowed

- “real malware detonation certified”;
- “AWS tested” or “MinIO tested”;
- “exactly-once”;
- “production-ready detection quality”;
- “no data loss” without a crash/restart test.

## Release sequence

1. Freeze features.
2. Run the final checks listed above.
3. Tag `4.3.0-rc1`, verify a clean download, then tag `4.3.0`.
4. Start the live-validation track (AP-126/AP-127) only after 4.3.0.
