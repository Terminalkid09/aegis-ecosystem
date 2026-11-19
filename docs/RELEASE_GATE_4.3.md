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

The bundle ships both the 4.3 Go agent and the legacy Guard/NodeTrace
artifacts. "No agent rollback" removes the downgrade requirement, not the
legacy runtimes: they remain the migration baseline.

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
| Bundle | `v4.3.0`, 28 files incl. the Go agent, manifest + `SHA256SUMS`, smoke from a copied bundle, `sha256sum -c` | **PASS, 28/28** |
| Clean install from bundle | source archive extracted from the bundle, new project/volumes/ports, image build, admin bootstrap, enrollment, heartbeat, agent event, alert Sigma `T1110.001`; frontend 200, Link UP, API smoke | **PASS, 21/21** |
| Clean install from Git clone | local clone of `31962cd` with no build outputs, new project/volumes; same install/enroll/event/alert/smoke path | **PASS, 21/21** |
| Unified agent from bundle | `unified-latest.zip` downloaded from the Brain bootstrap endpoint with a single-use token; binary ran as `agent_type=unified`, telemetry persisted, agent revoked | **PASS** |
| Version surfaces | Brain `/health/live`, frontend build, Guard POM, NodeTrace, Go agent | `4.3.0` |
| Go | `go test -count=1 ./...`; `--profile unified --check` | **PASS** |
| UI | `npm run build`; Playwright with Kraken seed | **13/13** |
| S3 adapter | Garage v2.5.0 upload/download/delete, two identical samples | **PASS** |
| Detection baseline | 14 malicious + 14 benign, synthetic | 14 TP, 0 FN, 5 FP, 9 TN |
| Diagrams | 4 draw.io sources + PNG/SVG, English, dark architecture system, version `4.3.0` | **4/4** |

The bundle now ships the Go agent for Windows and Linux as well as the legacy
Guard/NodeTrace artifacts. The live test downloads the agent from the bundle
through the same bootstrap endpoint the one-liner uses, so the installer path
is exercised, not only a local binary.

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
| 3 | Release bundle from a clean download | **PASS (local)** | 28-file `v4.3.0` bundle including the Go agent; manifest/checksums, copied-bundle smoke and `sha256sum -c` (28/28) pass, and `--require-agent` rejects a bundle without it. GitHub asset download, cosign/provenance verification remain tag-time work; the release is unsigned by decision (`docs/RELEASE_SIGNING.md`) |
| 4 | Upgrade from 4.2.1 | **PASS (server-only)** | 4.2.1 DB restored, 68 agents/321 alerts preserved, Brain 4.3.0 at Alembic head, smoke 21/21. Agent rollback is out of scope by decision |
| 5 | Hosted CI at the tag | **NOT RUN** | CI is tag/manual only. The `v4.3.0` tag workflow must be green before publishing; a local green run is not a substitute |
| 6 | **Clean install from the release bundle** | **PASS** | source archive extracted from `v4.3.0`, empty volumes, build + bootstrap + enrollment + event + alert + frontend/Link + smoke 21/21 |

The bundle is built from the HEAD commit recorded in
`RELEASE_MANIFEST.json`: `release-smoke.py` verifies 28/28 and
`sha256sum -c SHA256SUMS.txt` verifies 28/28 on Windows/Git Bash. Three
release-path defects were found and fixed before the tag. `SHA256SUMS.txt` was written with
platform newlines, so `sha256sum -c` failed on every name with a trailing `\r`
while the smoke test passed; and `git archive` applied `core.eol`, so
`aegis-source.tar.gz` shipped CRLF text in 729 files even though the blobs are
LF. The builder now writes LF checksums, archives with an explicit LF config,
fails if any text member still contains CR, and the smoke test rejects CR,
malformed, duplicate or missing checksum entries; negative tests exit 1. The
rebuilt source archive differs from the gate-6 archive only in docs,
`README.md` and the release scripts, so the clean-install evidence still covers
the shipped runtime code. The third defect was in the installer download
itself: `FileResponse` through Starlette 1.10.0's `BaseHTTPMiddleware`
returned `200` with the correct `Content-Length` and zero bytes, so no
one-liner could fetch its agent. The endpoint now returns the bounded
artifact bytes directly; a 14-byte probe and the 3.4 MB `unified-latest.zip`
both came back byte-identical, and a regression test covers it.

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
- the unified Go agent is in the bundle and was downloaded and run from the
  Brain installer endpoint;
- a frozen, synthetic detection baseline, not a production FP/FN rate;
- server upgrade from 4.2.1 with the database data preserved.

## Not allowed

- “4.3.0 released” or “production GA” while gate 5 is not green;
- “real malware detonation certified”;
- “AWS tested” or “MinIO tested”;
- “exactly-once”;
- “production-ready detection quality”;
- “agent rollback tested” (it is outside 4.3.0);
- “the unified service was installed on a target host” (artifact download and
  agent run were tested; service registration is still outside 4.3.0);
- “no data loss” without the process-kill test and restore drill.

## Release sequence

1. Commit the release state on `feat/4.3-agent-go`.
2. Create the annotated `v4.3.0` tag and push it only as the release action.
3. Run the tag workflow; require gate 5 green and verify the downloaded assets
   and provenance attestation.
4. Publish `v4.3.0`; do not create `4.3.0-rc1`.
5. Start AP-126/AP-127 live validation only after the 4.3.0 tag; no new
   firewall/DNS feature is part of 4.3.
