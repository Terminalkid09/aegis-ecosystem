# Aegis 4.3 — Release Gate

Status: 2026-11-22. **No `v4.3.0` tag has been cut and nothing is published.**
The 4.3 production-path work is on `release/4.3.0` (PR #18):
provider-agnostic Authenticode signing, production GPG mode, cosign keyless
release signing, RPM and ipk packages, xrdp log forwarding and AP-126/AP-127
harnesses. PR #18 is `MERGEABLE/CLEAN`; its branch CI and packaging runs are
green. The production validation harnesses are documented in
[PRODUCTION_VALIDATION.md](PRODUCTION_VALIDATION.md); they are not release
evidence until executed with the operator's certificate, tenant, lab, corpus
and a future scheduled soak. The hosted tag run, including the tag-only `release` job, is still
required before calling the release published. There is no `4.3.0-rc1`: the
release is cut directly as `v4.3.0`.

## 2026-11-20 local verification update

A fresh Git-clone style run was performed after the 4.3 security work. The
following results are local, reproducible evidence and **do not** replace the
hosted tag workflow:

- Brain: **902 passed, 4 skipped** against disposable PostgreSQL and real Redis
  (the skips include YARA rules unavailable for Python 3.15/Windows); command
  queue **8/8** on real Redis, including redelivery and process-restart recovery;
- Kraken: **154 passed**; frontend: production build **PASS**, lint
  **0 errors / 24 warnings**;
- Playwright pages/session/smoke/Kraken through Caddy: **13 passed**; the
  `users` spec assumes a single-admin database and was not part of this run;
  Playwright OIDC against Keycloak 26.0.7: **2 passed**; the manual SSO exchange
  returned **200** and replay **401**; API smoke **21/21**;
- ETW live elevated: **95 events** (45 created, 47 exited, 3 connections);
  non-elevated exit **2**, no session;
- WSL2 Ubuntu/Kali eBPF: **PASS**, benchmark **300/300**, zero loss (bare-metal
  remains a release gap);
- file secrets and Vault KV v2: **PASS**, including precedence and fail-closed
  empty-file handling;
- clean install core + Kraken: images rebuilt, admin bootstrap, API smoke
  **21/21**, Kraken and sensors healthy; signed ingest delivered one event to
  the Brain (`sent=1`);
- Windows Docker Desktop: the same Compose stack was **healthy** (Brain, Link,
  frontend, Caddy, Kraken, sensors, broker), with HTTP 200 from
  Brain/frontend/Kraken and Caddy. The Windows server MSI now packages that
  payload and was built plus administratively extracted. Aegis, Kraken and
  suite now pass a clean-host install/CLI/PATH/uninstall test on Windows; a
  pre-login service remains a host gate.

The post-audit hardening was re-verified live through Caddy: password reset
invalidates every pre-reset JWT and trusted device (DB `token_version`
incremented), SSO-only mode rejects local login and registration with **403**,
the OIDC callback without state fails closed without setting a session cookie,
HSTS is emitted only on HTTPS/trusted forwarded proto, and the session cookie
is `HttpOnly; Secure; SameSite=strict`. Alembic `0025_user_token_version` was
also tested with `upgrade head -> downgrade 0024 -> upgrade head` on a
disposable database. These checks complement, and do not replace, the hosted
tag workflow.

Four defects found by this run were fixed: the generated `ALLOWED_ORIGINS`
omitted `https://aegis.local` (403 on cookie-authenticated POST/PATCH through
Caddy); compose did not pass `OIDC_*`/`PUBLIC_BASE_URL` to the Brain; the SPA
did not hydrate an HttpOnly session created by the OIDC callback; and the
telemetry build tags excluded Darwin, so `SystemInfo`/`LocalMAC` were undefined
and macOS did not compile. The system-info file now includes darwin and the Go
matrix includes `macos-latest`. A Kraken startup `NameError` was also fixed.
Caddy now reads `AEGIS_DOMAIN`/`ACME_EMAIL` instead of a hardcoded domain, the
optional Prometheus scrape config is documented as a lab-only profile, and the
YARA engine has a dedicated Python 3.12 CI job (`yara_engine`) because
`yara-python` has no 3.15 wheel. The 3.15 suite still reports the three declared
skips; the new job is not a substitute for the hosted tag gate.

Still open: **Gate 5** (hosted tag workflow), macOS CI execution (the
`macos-latest` build/test job is configured, but no live Mac hardware or
endpoint telemetry is supported), bare-metal Linux, the server-package first
start/reboot on a real Linux Docker host, the Windows server MSI pre-login
service, Windows Server live validation, the production
certificate/key and MDM
tenant, the AP-126 isolated lab with an authorized sample, the AP-127 real
corpus, and true multi-host failover. **Do not publish/tag/push as a
release on the strength of this local run alone.**

## 2026-11-22 packaging and update verification

Executed locally in disposable containers (`debian:bookworm-slim` with systemd,
`fedora:40`, Docker Desktop 29.5.3). The running development stack was not
touched, and no release was published.

- **deb install** (`apt install ./aegis_4.3.0_amd64.deb`): `postinst` enables
  `aegis.service`, `/opt/aegis/server` payload present, `/etc/aegis/server.env`
  is `0600 root:root`, `ak 4.3.0`;
- **deb upgrade** 4.3.0 -> 4.3.1 via `ak update --version ... --from <dir>`:
  SHA-256 verified, CLI and package both 4.3.1;
- **downgrade guard**: 4.3.1 -> 4.3.0 without `--allow-downgrade` exits 1; with
  the flag it installs 4.3.0;
- **tampered checksum** and **missing sidecar** both exit 1 without touching the
  installed version;
- **suite** 4.3.0 -> 4.3.1 updates `aegis-suite`, `aegis` and `kraken` together;
- **RPM**: `dnf install` and `rpm -e` install and remove `aegis-agent` cleanly;
- **defect found and fixed**: `ak update` re-ran debconf and printed prompt text
  plus Perl warnings. The updater now runs non-interactively with conffile
  `--force-confdef`/`--force-confold`; re-tested 4.3.1 -> 4.3.2, zero prompt lines;
- **ICE61**: `wix msi validate` reports only `WIX1076/ICE61`; with `-sice ICE61`
  validation is clean. CI suppresses that single ICE by name;
- **`ak start --wait`** and the `ak doctor` resource report are covered by
  `scripts/tests/ak_smoke.sh` (PASS in WSL Ubuntu).

Still open after this run: a real `ak update` against GitHub assets (no published
release contains packages yet; the tag job is wired but has never executed), the
first start/reboot on a real Linux Docker host, and the Windows pre-login
service.

## Decision
## Decision

**4.3.0 is a product-complete controlled-pilot release, not a certified
malware-analysis release and not production GA.** The live install, enrollment,
event, detection, upgrade, bundle and clean-install paths have real evidence.
The tag may be created only after the hosted tag workflow is green.

The bundle ships only the 4.3 unified Go agent. Guard and NodeTrace remain in
the source tree for 4.2.1 compatibility, but they are not in the bundle and are
not offered by the 4.3 deployment UI. "No agent rollback" removes the
downgrade requirement; it does not leave a legacy artifact path in the bundle.

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
| Bundle | `v4.3.0`, 24 files incl. the four unified archives, manifest + `SHA256SUMS`, smoke from a copied bundle, `sha256sum -c` | **PASS, 24/24** |
| Clean install from bundle | source archive extracted from the bundle, new project/volumes/ports, image build, admin bootstrap, enrollment, heartbeat, agent event, alert Sigma `T1110.001`; frontend 200, Link UP, API smoke | **PASS, 21/21** |
| Clean install from Git clone | local clone of `31962cd` with no build outputs, new project/volumes; same install/enroll/event/alert/smoke path | **PASS, 21/21** |
| Unified agent from bundle | `unified-latest.zip` downloaded from the Brain bootstrap endpoint with a single-use token; binary ran as `agent_type=unified`, telemetry persisted, agent revoked | **PASS** |
| Version surfaces | Brain `/health/live`, frontend build, Guard POM, NodeTrace, Go agent | `4.3.0` |
| Go | `go test -count=1 ./...`; `--profile unified --check` | **PASS** |
| YARA engine | Python 3.12 container, `yara-python` 4.5.4, 3 engine tests | **PASS locally (3/3)**; hosted `yara_engine` job configured |
| macOS | `GOOS=darwin GOARCH=arm64/amd64 go build`; Darwin test compile + `go vet` | **PASS locally**; `macos-latest` CI run pending; no endpoint telemetry support |
| UI | `npm run build`; Playwright Caddy + Kraken, SSO separately | **13 passed; SSO exchange 200, replay 401** |
| S3 adapter | Garage v2.5.0 upload/download/delete, two identical samples | **PASS** |
| Detection baseline | 14 malicious + 14 benign, synthetic | 14 TP, 0 FN, 5 FP, 9 TN |
| Diagrams | 4 draw.io sources + PNG/SVG, English, dark architecture system, version `4.3.0` | **4/4** |

The bundle ships only the unified Go agent for Windows and Linux; macOS is not
shipped as a supported telemetry target. The Windows
archive contains `aegis-agent.exe` and `aegis-etw.exe`; the Linux archive
contains `aegis-agent`, `aegis-collector` and `aegis_exec.bpf.o`. The live test
downloads the agent from the bundle through the same bootstrap endpoint the
one-liner uses, so the installer path is exercised, not only a local binary.

The 50k run is documented in `docs/benchmarks/4.3/link-load-50k.md`. It proves
the Link HTTP + Redis Lua boundary on one Docker Desktop host; it does not
prove a multi-host cluster, TLS throughput or 50,000 independent agent
processes. The clean-install test proves the Compose/API path, not the native
Windows/Linux agent service packaging.

## Soak decision

The 4.3.0 controlled pilot ships **without a new seven-day soak**. The v4.0.0
soak passed, the 4.3 delta is small, and the risk is accepted rather than
hidden: the current 4.3 sample only proves the harness starts. The soak is
deferred to the next Aegis feature cycle, after firewall/DNS policy and the
sensor/telemetry/process work; the sequence is Aegis soak, Aegis release,
Kraken soak, Kraken release. It is not a 4.3 gate and not a customer step.

## Six gates

| # | Gate | Status | Evidence / what remains |
|---|---|---|---|
| 1 | **AP-122** Link atomic check+push and 50k load | **PASS** | 50k live run above; raw evidence retained |
| 2 | **AP-123** crash/restart and duplicate visibility | **PASS** | process restart/`attempt=2` and idempotent ack pass; OTA UI says `queued — not executed` and explains the ack/replay boundary |
| 3 | Release bundle from a clean download | **PASS (local)** | 24-file `v4.3.0` unified-only bundle; manifest/checksums, copied-bundle smoke and `sha256sum -c` (24/24) pass, and `--require-agent` rejects a bundle without the four archives or the kernel helpers and rejects legacy/raw artifacts. GitHub asset download and cosign/provenance verification remain tag-time work; the tag workflow signs `SHA256SUMS.txt` with cosign keyless OIDC and verifies it before publishing (`docs/RELEASE_SIGNING.md`) |
| 4 | Upgrade from 4.2.1 | **PASS (server-only)** | 4.2.1 DB restored, 68 agents/321 alerts preserved, Brain 4.3.0 at Alembic head, smoke 21/21. Agent rollback is out of scope by decision |
| 5 | Hosted CI at the tag | **NOT RUN** | CI is tag/manual only. The `v4.3.0` tag workflow must be green before publishing; a local green run is not a substitute |
| 6 | **Clean install from the release bundle** | **PASS** | source archive extracted from `v4.3.0`, empty volumes, build + bootstrap + enrollment + event + alert + frontend/Link + smoke 21/21 |

The bundle is built from the HEAD commit recorded in
`RELEASE_MANIFEST.json`: `release-smoke.py` verifies 24/24 and
`sha256sum -c SHA256SUMS.txt` verifies 24/24 on Windows/Git Bash. Three
release-path defects were found and fixed before the tag. `SHA256SUMS.txt` was written with
platform newlines, so `sha256sum -c` failed on every name with a trailing `\r`
while the smoke test passed; and `git archive` applied `core.eol`, so
`aegis-source.tar.gz` shipped CRLF text in 729 files even though the blobs are
LF. The builder now writes LF checksums, archives with an explicit LF config,
fails if any text member still contains CR, and the smoke test rejects CR,
malformed, duplicate or missing checksum entries; negative tests exit 1. The
rebuilt source archive also carries the artifact-download fix, the unified
defaults and the release-script changes. Gate 6 ran on the `31962cd` archive;
the final bundle was verified with 24/24 smoke and the live unified-agent
download/run against a 4.3 Brain. A full image rebuild from the final source
was not repeated locally because the PyPI fetch timed out; the hosted tag
workflow is the clean-build gate. The third defect was in the installer download
itself: `FileResponse` through Starlette 1.10.0's `BaseHTTPMiddleware`
returned `200` with the correct `Content-Length` and zero bytes, so no
one-liner could fetch its agent. The endpoint now returns the bounded
artifact bytes directly; a 14-byte probe and the 3.4 MB `unified-latest.zip`
both came back byte-identical, and a regression test covers it.

**Gate 5 is the only remaining gate in this document**, but it is not the only
production input: the real Authenticode certificate, GPG key, MDM tenant and
authorized AP-126/AP-127 lab/corpus are operator-supplied evidence (see
“Production gaps in 4.3”). Do not publish the tag or call 4.3.0 released until
the hosted run is green and its artifacts are verified. The branch CI at
`a6b0343` (run 44936999687) is green for every non-release job: lint, contract,
Go on Linux/Windows/macOS, Windows installers, OS compatibility, build/test,
YARA, supply chain, NodeTrace Windows, Kraken and Compose E2E. `Release
Artifacts` was skipped because it is tag-only. A green branch run does **not**
prove the publishing job; the tag is still required.

## Production gaps in 4.3

The 4.3 branch now contains the executable production paths; these are the
remaining operator inputs and evidence, not missing packaging code:

- **Delivered:** signed MSI/deb/rpm/ipk paths, native service drop-in,
  provider-agnostic Authenticode signing, production GPG mode, cosign keyless
  release signing and clean-host install/uninstall CI;
- **External input for production GA:** the real Authenticode certificate/key
  and protected GPG key must be supplied by the operator. The 4.3 controlled
  pilot accepts explicitly labelled self-signed packages; production GA still
  requires `mode=production`, a `Valid` Authenticode signature with timestamp
  and the operator GPG key;
- **External input:** MDM/Intune/GPO tenant validation requires the customer's
  tenant; the clean Windows runner and MSI properties are ready;
- **Deferred by decision:** the seven-day soak (`scripts/soak_7d.py`) is an
  internal endurance harness. 4.3.0 ships without a new run; the v4.0.0 soak
  passed and the 4.3 delta is small. It is not shipped in any MSI/deb/server
  package, not a 4.3 gate and not a customer prerequisite. It is scheduled for
  the next Aegis feature cycle, followed by the Kraken soak, as documented in
  [PRODUCTION_VALIDATION.md](PRODUCTION_VALIDATION.md);
- **AP-126:** the bounded sandbox harness is shipped; executing live malware
  requires an authorized sample and an isolated, snapshot/restore-capable lab;
- **AP-127:** the labelled-corpus gate with recall/FPR and per-host/day metrics
  is shipped; a production quality claim requires the real corpus;
- external security review/pen test and a backup/restore drill;
- multi-host Redis/Postgres failure tests and a documented support model.

AP-126/AP-127 are **inside the 4.3 production gate**. The repository does not
fabricate real-malware or real-corpus results: it ships the safe harness and
the gate, and the operator supplies the authorized lab and corpus.

AWS/MinIO remains optional by design; Garage and local storage are supported
for the pilot. AWS is not certified.

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

- “4.3.0 released” while gate 5 is not green; “production GA” while the
  production certificate/key and real lab/corpus evidence are missing. The
  controlled pilot may use explicitly labelled self-signed packages; that is not
  a production-GA claim;
- “real malware detonation certified”;
- “AWS tested” or “MinIO tested”;
- “exactly-once”;
- “production-ready detection quality” without the AP-127 real corpus;
- “agent rollback tested” (it is outside 4.3.0);
- “the unified service was installed on a target host” (artifact download and
  agent run were tested; service registration is still outside 4.3.0);
- “no data loss” without the process-kill test and restore drill.

## Release sequence

1. Merge PR #18 into `dev`, then open and merge the release PR into `main`.
2. Create the annotated `v4.3.0` tag from `main` and push it only as the release action.
3. Run the tag workflow; require gate 5 green and verify the downloaded assets
   and the cosign/provenance evidence.
4. Publish `v4.3.0`; do not create `4.3.0-rc1`.
5. Attach the authorized AP-126/AP-127 lab and corpus evidence and the real
   certificate/key/MDM evidence as part of the 4.3 production gate; no new
   firewall/DNS feature is part of 4.3.
