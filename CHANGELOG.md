# Changelog

All notable changes to Aegis Ecosystem are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Semantic Versioning applies to releases after `v4.0.0`. The older tags
`v1.0.0`–`v4.0.0` were batch labels, not complete SemVer releases; they remain
published and are not rewritten. See [docs/RELEASES.md](docs/RELEASES.md) for
the tag audit and the release policy.

> A published version is immutable. `v4.1.0` is the first complete release
> after the batch tags: the full Kraken vertical ships with the hardening
> fixes, and expansion moves to 4.2+.

## [Unreleased]

### Fixed

- `aegis-agent` derives the heartbeat, update, command, ack and report
  endpoints from `AEGIS_BRAIN_URL` / `BRAIN_URL` when only the server URL is
  configured. Previously every endpoint stayed empty and a correctly configuredendpoint refused to start
  with `endpoint heartbeat is not configured`; the
  register URL no longer doubles the `/api/v1` prefix.
- `aegis-agent -check` is a real pre-flight check: it exits 1 for a missing
  server URL, a malformed endpoint or an explicit `-config` that does not
  exist, and only warns when the enrollment token has not been provisioned yet.
- `docker-compose.ha.yml` merges with the base file again. The overlay set
  `deploy.resources` while the base kept the legacy `cpus`, `mem_limit` and
  `pids_limit` keys, which Compose rejects with `can't set distinct values`; the
  overlay now resets those keys before applying the HA limits.

### CI

- The lint job validates every compose overlay (`prod`, `ha`, `mtls`,
  `observability`, `kraken-honeypot`) with `docker compose config`.
- A `version_guard` job runs before the packaging jobs on a `v*` tag and fails
  when the tag does not match the version literals embedded in
  `packaging.yml`, so a mislabelled release cannot publish artifacts for the
  previous version.

## [4.3.0] - 2026-11-23

### Server packaging and persistence (2026-11-22)

- `ak update` is no longer interactive: apt/dpkg run with
  `DEBIAN_FRONTEND=noninteractive` and `--force-confdef`/`--force-confold`, so a
  remote update does not stop on a debconf question and does not rewrite
  `server.env`/`kraken.env`. Found while testing 4.3.0 -> 4.3.1 in a container.
- `ak start --wait` (with `--timeout`, default 300s per component) waits for the
  containers to be running and free of `starting`/`unhealthy` health states; on
  Windows the behaviour was already `compose up --wait` and it now accepts the
  same flags.
- `ak doctor` reports the memory budget: host RAM, Docker engine limit, usage
  per container and, inside WSL, a reminder that the number is the VM ceiling,
  not Aegis consumption.
- CI: a `release_assets` job on `v*` tags that waits for the release created by
  `ci.yml` and attaches the packages with their checksums, without ever
  overwriting a published asset; MSI validation suppresses only `ICE61`
  (intentional downgrade) and keeps the other ICE checks active.

- Added the complete `aegis` package (Brain, Link, dashboard/frontend,
  PostgreSQL, Redis, Caddy, backup) and `kraken` (app, sensors, broker, RDP,
  private database and Redis), plus the `aegis-suite` meta-package and the
  `aegis-suite-<version>.tar.gz` bundle to download both stacks together. Each
  stack keeps its own systemd unit, its own secrets in `/etc/aegis/*.env` and
  its own lifecycle; the MSI/deb agent stays endpoint-only and the bundle does
  not install it on the server.
- `aegis-suite` is not just a dependency list: its post-install creates the
  shared `aegis_shared` network, aligns the SSO/ingest secrets, points Kraken to
  `aegis-brain:8000`, enables the integration and serves the UI under
  `/kraken/`. Installing the two packages separately does not connect them.
- Added the `ak` operational command, exposed by both server packages through
  `update-alternatives` with no file conflicts: `ak start/stop/restart` manage
  systemd, while `ak status/ps/logs/doctor/url` show the real state of units and
  containers. `ak configure` changes public hostname, ACME email, public URL and
  local port without rewriting the secrets. `ak --help` and `ak help <command>`
  are the local documentation; the server stays headless and does not create a
  desktop icon. Full reference in `docs/AK_CLI.md`.
- The dashboard is no longer hard-wired to host port 3000: `AEGIS_UI_PORT` is
  configurable, the package automatically picks the first free slot in
  `3000-3099` if the requested port is taken and records the value in
  `/etc/aegis/server.env`. The `aegis` installation uses debconf for domain,
  ACME email and port; the same values can be preseeded through the environment
  or changed with `ak configure`. The public domain stays distinct from the
  Docker Desktop path of the MSI agent.
- The Windows matrix is now complete like the deb one: `aegis-server` installs
  only Aegis, `kraken-server` only Kraken, `aegis-suite` both; the agent MSI
  stays endpoint-only. Every package is self-sufficient, exposes `ak.cmd` on the
  machine `PATH` and generates its own `server.env`/`kraken.env` on the first
  `ak start`. Aegis and suite ask for FQDN/ACME email/port; Kraken-only has no
  public TLS edge. They use Docker Desktop, so startup happens at login
  (`ak start` or a scheduled task), not before login.
- Added `ak update` on Linux and Windows: it resolves the latest stable release
  or an explicit version, verifies the SHA-256 checksum, preserves
  FQDN/email/port, updates the CLI and payload and restarts the services. A
  downgrade requires `--allow-downgrade` and a verified database backup. Added
  the [release policy](docs/RELEASE_POLICY.md): 4.3.x current, 4.2.x previous,
  <=4.1.x EOL; published artifacts stay immutable.
- Stricter FQDN/email validation on Linux and Windows, rejecting a public
  domain without an ACME email, an inconsistent public URL and invalid DNS
  labels. The Windows configuration stays valid for Kraken-only too, which uses
  a separate env.
- Verified the Aegis+Kraken stack on Docker Desktop/Windows: Brain, Link,
  frontend, Caddy, Kraken, sensors and broker healthy, HTTP 200 on Brain,
  frontend, Kraken and Caddy. The Windows package reuses the same runtime and
  the same source; what remains is a boot-timing difference, not a missing
  component.
- The default signing of the server packages is self-signed (local GPG key
  exported as `aegis-pilot-signing-key.asc`): it is accepted for the pilot, it is
  not a public identity and it is never labelled as production. Production
  signing remains an operator input. GPG is optional for a local pilot:
  `SIGNING_MODE=unsigned` is available and SHA-256 remains the integrity check.
- The 7-day soak is declared an internal test and **postponed to the next
  cycle**, after firewall/DNS and the improvements to sensors, telemetry and
  processes. 4.3.0 does not wait for it: the v4.0.0 soak had passed and the 4.3
  delta is small; the first 4.3 sample is not a completed soak. The runner is
  not in the packages and is not a request to the customer.
- Documented the WSL2 reset (`wsl --shutdown`) that fixed the
  `HCS_E_CONNECTION_TIMEOUT` timeout of the VM shared with Docker Desktop.

### Deep validation and detection hardening (2026-11-23)

- Added `scripts/deep_simulation.py`: end-to-end simulation against the real MSI
  stack, with 39 malicious cases, 46 benign ones and the dual-use cases sent as
  real events through the enrollment flow. Every case uses a dedicated agent, so
  alert suppression per agent/rule/process cannot skew the count. Report in
  `docs/benchmarks/4.3/DEEP_SIMULATION.md` next to the raw JSON; reproducible
  without changing the product.
- Result of the recorded run (738 s): TP 38, FN 1, FP 0, TN 46, precision 1.000,
  recall 0.974, F1 0.987, false positive rate 0.000, correct severity 23/28, and
  40/40 functional checks PASS (alert lifecycle, viewer RBAC, isolation,
  telemetry, resolver, Kraken ingest and outbox). The single FN is declared:
  `/etc/shadow` (T1003.008) has no static rule and requires file-access auditing
  that this event set does not collect.
- Soak of 10 agents × 120 s in the same run: 15,860 requests accepted, 0 errors,
  0 lost events, 132.07 rps, p50/p95/p99 74.1/98.0/178.5 ms. It does not replace
  the 7-day soak, which remains postponed to the next cycle.
- Removed four false positives measured on clean hosts (`vssadmin list
  shadows`, `schtasks /change`, `curl https`, `explorer → cmd`) and added 15
  regression tests in `aegis-brain/tests/test_detection_hardening.py`.
- Process, module and anomaly lists are capped at 500/256/200 items and, when
  the limit is hit, the response carries the `quality` marker. A 600-process
  payload used to be rejected with 422 and the telemetry of the whole event was
  lost; now the event goes through and the truncation is declared.
- Reopening an alert clears the pattern suppression, so a manual reopen does not
  leave the detection muted for a week.
- CI: the deb content checks used `grep -q` in a pipeline; grep closes the
  stream, the producer dies with SIGPIPE and the step failed even though the
  check was correct. Grep now reads the file and the exit status is the check's.
- Enrollment limit documented instead of changed just before the tag: `/enroll`
  accepts 10 requests per minute per source IP and it is an anti-brute-force
  control, not a parameter to raise. The runbook explains how to enroll a fleet
  in batches; the agent retry that honours `Retry-After`/`X-RateLimit-Reset` and
  the Windows service recovery are planned for 4.4.

### Aegis Agent 4.3.0 — NodeTrace and Guard functional parity

**Status: 4.3.0 release for controlled pilots.** The Go runtime and the
`unified` profile are verified against the real Brain; the release is not
production GA and does not claim malware certification. The 4.3 bundle no
longer contains Guard Java and NodeTrace Python: they remain only in the source
for 4.2.1 compatibility and cannot be offered for new deployments. Rolling back
to the legacy agents is not a 4.3.0 requirement and is explicitly out of scope.

NodeTrace (`sensor`) was verified with the Python suite (82 tests, 2 skips) and
with 84 Go test functions across all packages. The binary live test covers
enrollment, CSR, `token.json`, heartbeat, `/update`, commands, ack, scan and the
`X-Client-Cert-Hash` header; it ran both against a fake Brain and against the
real local Brain, with telemetry persisted in PostgreSQL.

Guard (`endpoint`) was ported by capability, not as a mechanical translation of
the 140 JUnit tests: `secret.json`/`agent_id`, `/enroll/enroll` enrollment, batch
outbox 25/500 ms with a 2,000 buffer, 50 MB AES-256-GCM spool with quarantine of
corrupt files, fsnotify FIM, fail-closed YARA CLI, ETW consumer, process monitor
with PID+start time, registry/services/persistence/Defender/Authenticode and the
14 actions (kill, kill tree, block IP and temporary block, quarantine, remove
persistence, DNS sinkhole, collect IOC, verify, isolate/deisolate, FIM, YARA,
delegated update). The binary live test covers identity, heartbeat/metrics,
commands, ack and the `X-Client-Cert-Hash` header; against the real Brain the
endpoint profile reported FIM and response actions active, with ETW/YARA
declared unavailable on this host.

The `unified` profile uses a single Guard identity and a single outbox, but also
starts the sensor collectors. The Brain/UI accept it in enrollment, deploy
tokens, jobs, OTA, Discovery and recent telemetry. The 4.3.0 bundle contains
only the Go agent for Windows and Linux: `unified-latest.zip`,
`unified-latest.tar.gz` and the versioned copies `unified-4.3.0.*`. The Windows
archive includes `aegis-agent.exe` and `aegis-etw.exe`; the Linux one includes
`aegis-agent`, `aegis-collector` and `aegis_exec.bpf.o`. `release-smoke.py
--require-agent` rejects a bundle without these files and explicitly rejects
Guard/NodeTrace and the raw binaries. The signed drop-in service/installer is in
4.3; the Java/JRE/Python rollback remains out of scope, together with real
malware and corpus certification.

Evidence run on 2026-11-18 (fake) and 2026-11-19 (real stack):

| Gate | Result |
|---|---|
| `go test ./... -count=1` | 84 Go test functions, all packages green |
| `go vet ./...` | green |
| Go build on Windows and Linux | green, Go 1.27.4 |
| `mvn test` Guard Java | 140 JUnit tests, 0 failure/error (Temurin 25.0.5.8) |
| NodeTrace Python | 82 tests, 0 failure, 2 skips |
| live sensor/Guard against a fake Brain | green; network and command contract observed |
| live sensor/endpoint/unified against the real Brain | green; telemetry rows 1/18/17, capabilities populated |
| first unified start with a single-use token | token consumed, agent_type=unified, telemetry present |
| unified deploy API | token 200, install.ps1/sh 200, job `manual_required`; only `oneline` accepted, no SSH/WinRM executor |
| agent runtime bundle | `unified-latest.zip` downloaded from the 4.3 Brain, run as `agent_type=unified`, telemetry persisted and agent revoked |
| local 2×8 s A/B | NodeTrace 27.28 MB RSS vs Go sensor 18.43 MB; Guard Java 126.45 MB vs Go endpoint 18.77 MB |

The benchmark is in `docs/BENCHMARK.md` and the raw data in
`docs/benchmarks/4.3/agents-ab.json`. It measures footprint and startup against
a fake Brain, not PostgreSQL ingestion, mTLS/Caddy or fleet behaviour. The
measured advantage is the reduction in RSS and artifact size; the CPU of the Go
endpoint is comparable to Java and is not claimed to be lower. During the
measurement a real Windows polling regression was fixed (WMI/Authenticode for
every process every second), which saturated a core.

**Declared scope:** 4.3.0 includes the signed MSI/deb/RPM/ipk packaging paths,
the native service, provider-agnostic Authenticode signing, GPG production mode
and cosign keyless signing of the tag. Out of scope: the Java/JRE/Python
rollback and real malware/corpus certification, which require an authorised
laboratory. The smoke test against the real Brain is real, but it is not a fleet
test or an installed-service test. The bundle no longer contains Guard/NodeTrace,
which remain only in the source for already installed 4.2.1 deployments.

**Release evidence:** isolated clean install from source with no artifacts
(`aegis-clean43`) with new volumes, admin bootstrap, real enrollment, heartbeat,
agent event, Sigma alert `T1110.001`, frontend and Link health;
`api_smoke.py` **21/21 ALL PASS**. The gate-6 clean install ran on archive
`31962cd`; the final bundle adds the download fix and the `unified` defaults, and
is verified with a 24/24 smoke plus the live download/run of the Go agent
against a 4.3 Brain. The bundle has 24 files: four `unified-*` archives and the
three kernel helpers inside the archives; the 4.2.1 database upgrade preserved
68 agents and 321 alerts, with a 21/21 smoke. The 50k Link load, the command
consumer restart and the gates remain recorded in `docs/RELEASE_GATE_4.3.md`.
The hosted CI at the tag is the only step still external to the local repository.

### Changed

- Unified agent modes: the single `agent_type=unified` agent now accepts
  `full`, `sensor` and `endpoint` capabilities through the token, installer,
  environment or `--mode`. A sensor-only unified agent does not start process
  monitoring, FIM, response actions or ETW; an endpoint-only agent does not
  start host telemetry or network scan. The agent record, binary, identity and
  enrollment remain one.
- Deployment Manager no longer offers or implies SSH/WinRM execution. The only
  rollout path is a short-lived token plus a one-liner copied to the target;
  the target must reach Aegis to download, enroll and heartbeat.
- Kraken sensors are internal by default. The honeypot is exposed only with the
  explicit `docker-compose.kraken-honeypot.yml` overlay, loopback-bound unless
  the operator sets `KRAKEN_HONEYPOT_BIND_IP=0.0.0.0`. SSH/HTTP are the default
  protocols; FTP/Telnet/SMB/RDP are opt-in.
- Docker Compose applies CPU/RAM/PID limits, `no-new-privileges` and
  capability drops to the application services; the sandbox broker now runs as
  a non-root user with the Docker socket group added explicitly.
- CI now runs on `dev`, `main`, `feat/**` and pull requests as well as tags. The
  release/publish job remains tag-only; a branch run is not Gate 5.
- Go toolchain bumped to **1.27.4** (latest stable, including the security fixes
  of 2 November 2026) in `aegis-agent/go.mod`, in the 4.3 plan and in CI, which
  now runs `go test`, `go vet` and a binary build on Ubuntu and Windows. The
  development machine was moved from Go 1.26.5 to 1.27.4 through the official
  package; `go version` and `go env GOROOT` now point to the new installation.

### Added

- Production validation harness: `scripts/soak_7d.py` (seven-day endurance with
  readiness, lost-event and RSS sampling), `scripts/dr_drill.sh` (encrypted DB
  plus PKI restore), `scripts/ha_failure_drill.sh` (same-host replica loss) and
  `scripts/multi_host_failure_drill.sh` (external PG/Redis failover trigger).
  They emit JSON evidence and fail closed on missing inputs; none is a
  substitute for the real run. `docs/PRODUCTION_VALIDATION.md` defines the
  operator inputs and the acceptance boundary.
- AP-126 evidence gate (`scripts/ap126_evidence.py`) and a three-node Kraken
  lab simulation (`deploy/kraken-lab/`). The lab is explicitly single-host,
  not a true multi-host or network-partition test.
- Optional Intune/GPO wrappers for the existing MSI (`deploy/mdm/`). They do not
  replace the MSI or the default one-liner: they verify the production
  signature, provision the one-shot token and provide local post-deployment
  validation. A real tenant is still required for tenant evidence.
- `scripts/install-autostart.ps1` and `docs/PERSISTENCE.md` make the reboot
  contract explicit for Docker Desktop, Linux Docker Engine, the Windows MSI,
  systemd and OpenWrt. The helper only configures the current user's Docker
  Desktop startup; it does not claim pre-login server availability.
- `scripts/persistence_check.py` verifies the checked-in reboot/crash contracts
  without changing the host. `--live-linux`, `--live-windows` and `--containers`
  are explicit opt-ins; a manually started agent is reported as not installed.
- Package builds now write a `.signing.json` sidecar with `mode=test`,
  `production` or `unsigned`. Test-signed CI artifacts cannot be mistaken for a
  release artifact, and a production release requires a `Valid` Authenticode
  signature with timestamp (MSI) or the operator GPG key (deb).
- Live integration test of the Go sensor against a fake Brain: enrollment, CSR
  signed by a test CA, identity persistence, heartbeat/telemetry, batch
  commands, ack, Discovery scan and verification of the `X-Client-Cert-Hash`
  header.
- Real live runs of the `sensor`, `endpoint` and `unified` profiles against the
  local Brain: `scripts/live_agent_profiles.py`; first unified start with a
  single-use token and generated install.ps1/install.sh, both syntax-checked.
- Guard `endpoint` profile baseline: `secret.json`/`agent_id`, `aegis-guard`
  enrollment, legacy reporting and the command validation layer; integration
  tests against a fake Brain and tests of the pure functions.

### Fixed

- `scripts/setup.py` initialises the PKI (CA + manifest key) after readiness and
  before the admin/smoke step. Without this step a clean clone served the
  one-liner installer with `503` even though the stack was healthy.
- Persistence: the MSI configures recovery for the `AegisAgent` service (three
  restarts at 5 s, reset after a day) in addition to automatic startup; the
  Linux unit uses `Restart=always` and `StartLimitIntervalSec=0`; the Windows
  one-liner verifies `AUTOMATIC` and the failure actions before declaring
  success, and waits for a service marked for deletion to finish. The deb/RPM
  packages and the ipk fail the installation if they cannot enable the service
  at boot. Compose containers use `restart: unless-stopped`, but require the
  Docker daemon to be enabled. `docs/PERSISTENCE.md` separates what really comes
  back from what depends on the host or the lab.
- The `scripts/soak_7d.py` soak keeps Windows awake with `ES_SYSTEM_REQUIRED`
  and fails if the wall clock has a gap larger than two sampling intervals. A
  sleeping laptop no longer produces a fake "7 days": the report declares
  `sleep_guard`, the gaps and `require_continuous`.
- Removed the experimental `scripts/self_improvement.py` prototype and its test.
  4.3 no longer contains any self-modifying detection component; AP-126/AP-127
  remain external-evidence gates, not self-improvement.
- CI now derives the Docker socket GID for the non-root Kraken broker and
  validates Vault addresses before `urlopen`; the Vault SSL context still uses
  the verified constructor with an explicit lab-only opt-out. Live telemetry
  tests skip on Darwin, where the collector is unsupported, while the macOS
  build/vet gate remains. Branch run 44916543187 is green for all non-release
  jobs; the release job remains tag-only.
- The legacy NodeTrace and Guard clients now send only `X-Client-Cert-Hash`,
  consistent with the Brain rejecting `X-Client-Cert`; the NodeTrace test blocks
  the return of the full header.
- Guard/Go handlers no longer report `ok` when quarantine, firewall block, kill
  or IOC collection fail: the error is propagated to the ack as `failed`.
- Kraken SSH now advertises an Ubuntu OpenSSH banner instead of the AsyncSSH
  default. FTP passive mode advertises a reachable host and a published passive
  range, and uploads complete on the data channel instead of a fixed sleep.
- The Kraken README no longer claims four sensors, a Docker socket in the app
  or 65+ tests; it documents six sensors, the broker-only socket and 154 tests.
- HA documentation no longer reports AP-122/AP-123 as open; both are PASS in
  the 4.3 release gate. Threat-model migrations now cite `0001..0025`.
- The artifact download (`/deploy/artifacts` and `/deploy/bootstrap-artifacts`)
  returned a `200` with a correct `Content-Length` but zero bytes:
  `FileResponse` through Starlette 1.10.0's `BaseHTTPMiddleware` lost the body,
  so no one-liner could download the agent. The response now reads the artifact
  into memory (a few MB) and a regression test covers the case.

## [4.2.1] - 2026-11-18

The `v4.2.0` tag was created but produced no GitHub Release: its release
workflow stopped in the NodeTrace Windows package because
`nodetrace-agent.spec` was ignored and absent from the tag. `v4.2.1` tracks the
spec, runs that package job on pull requests, and is the first complete 4.2
release.

### Kraken expansion and unified SOC

- Kraken outbox batches 500 deliveries, retries only rejected events, isolates
  poison events and exposes lag metrics; lab context remains `shadow` end to
  end. Brain migration `0021` and the replay script cover deception sessions.
- Six deception Sigma rules plus `multi_sensor_same_ip` correlation, and a
  unified timeline over SIEM, deception, alert, incident and telemetry sources.
- Kraken operations UI for campaigns, sensors/fleet, topologies and Lab runs;
  Brain remains read-only. SMB and RDP sensors capture NetNTLMv2/decoy access
  and negotiation banners without relaying credentials.
- ATT&CK coverage and governed suppressions: TTL is mandatory, capped at 90
  days, and hidden-alert counts remain visible.
- Real mTLS fingerprint enforcement rejects the legacy full-certificate header;
  Guard and NodeTrace send only `X-Client-Cert-Hash`. Brain runs two workers
  with Redis-backed rate limiting.
- File intelligence is an opt-in asynchronous static-analysis job: bounded
  upload, ZIP manifest, IOC extraction and a Sigma candidate with low
  confidence and explicit provenance. The sample stays in Kraken's storage and
  deletion is verified; no detonation or network execution is implemented.

### Performance and operational hardening

- Telemetry ingestion reuses the authenticated Agent, caches the Argon2 secret
  check for 60 seconds, throttles `last_seen` writes to 30 seconds, and fetches
  context/custom rules only when a rule actually fires. Device tokens also carry
  a SHA-256 proof bound to the current Argon2 hash: a restarted worker verifies
  them without the expensive KDF, while re-enrollment/revocation invalidate the
  proof automatically and the DB revocation check still runs on every request.
- The durable, unique-event path now meets the 200 rps gate on the default
  **2-worker** stack: **289.35 rps through Caddy/TLS** (1.500/1.500 `200`,
  p50 99.1 ms, p95 159.9 ms, p99 188.8 ms) and **247.76 rps direct**
  (3.000/3.000 `200`, 3.008 DB rows, p95 194.4 ms). A 20-agent cold proof
  burst reaches **341.16 rps** (p95 52.3 ms); 100 warm events reach
  **301.16 rps** (p95 91.5 ms). Legacy agents take 79.4 ms on first contact
  and 38.7 ms after the proof backfill, with no read timeouts. The earlier
  **96–111.58 rps** figure came from the non-default 8-worker setup and is
  superseded; `synchronous_commit` remains `on`.
- The Kraken sensors container now exposes a localhost-only health listener on
  port 8000. The Docker healthcheck no longer probes a honeypot port, so it
  cannot create fake attack events; the container reports `healthy`.

### Release engineering

- The NodeTrace Windows package is built and uploaded on pull requests as well
  as tags, so the release-only path is tested before an immutable tag. The
  PyInstaller spec is tracked in the repository instead of being ignored.
- The release bundle uses `env.example`, the portable name GitHub does not
  rewrite, and the installers accept either `env.example` or `.env.example`.
- The tag workflow builds the Windows NodeTrace package and includes it in the
  bundle; no manual upload is required.
- The tag workflow generates one CycloneDX SBOM per release image, records them
  in `RELEASE_MANIFEST.json`, and runs `release-smoke.py` before publishing.
- The tag workflow produces a GitHub build-provenance attestation for the
  release assets. `docs/RELEASE_SIGNING.md` records the 4.2 decision:
  checksummed, not signed; provenance is verifiable but does not authenticate
  the publisher.
- The `e2e` CI job starts an ephemeral Compose stack, seeds a deterministic
  Kraken event and runs `api_smoke.py` plus Playwright pages/session/Kraken.
- Five operational runbooks cover compromised agents, Brain, Kraken, malware
  escape and backup/restore.

## [4.1.0] - 2026-11-16

The complete Kraken vertical: transactional outbox and retry, delegated SSO,
mounted UI, read-only Aegis view and the isolated compose profile.

### Added

- Gate 0 licensing groundwork: `LICENSE` (AGPL-3.0-only), `NOTICE`,
  `TRADEMARK.md`, `SECURITY.md`, `CONTRIBUTING.md`, and the
  `THIRD_PARTY_NOTICES.md` placeholder.
- `docs/archive/PLAN_AEGIS_KRAKEN_HANDOFF.md` v2.7: the 4.1 scope is the complete
  Kraken vertical (compose, signed ingest with outbox/retry, UI, read-only
  Aegis view, end-to-end smoke test); new sensors, campaigns, Lab and unified
  timeline move to 4.2+.
- `docs/RELEASES.md`: audit of the published tags, the release checklist and
  the release-integrity gate: no user-visible capability is called integrated
  until API, UI, docs and tests ship together. The gate now names the complete
  Kraken vertical as a 4.1 requirement.
- `docs/archive/ROADMAP.md`: explicit OSINT/SentinelX and deploy/fleet
  workstreams, separate from the release hardening checklist.
- `docs/youtrack_tickets.csv` and `scripts/youtrack_import.py`: import path for
  the findings and roadmap work packages.
- `scripts/test-restore.sh` and the nightly `Backup Restore Check` workflow:
  an encrypted backup/restore round-trip creates disposable databases and
  verifies a probe row instead of trusting the restore path by inspection.
- Kraken transactional outbox (4.1.7): the signed event is queued in the same
  transaction as the attack record, then delivered by a worker with exponential
  backoff, poison handling, stale-claim recovery and `kraken_outbox_*` metrics.
  A Brain outage no longer drops the event from the Aegis side; retries are
  idempotent because the Brain deduplicates by `event_id`.
- Kraken UI and unified Aegis view (4.1.8): Kraken is served behind `/kraken/`
  with delegated SSO — a 60-second, single-use assertion signed with the
  dedicated `KRAKEN_SSO_SECRET` — and keeps its own users, database and cookie
  scope. The UI loads only local assets and no inline JavaScript, so it works
  under the `script-src 'self'` CSP and in air-gapped deployments. The Aegis
  SPA adds a read-only Kraken page with the related events, alerts and
  incidents; Kraken-specific operations stay in the Kraken UI.
- Kraken in the root compose (4.1.9): a `kraken` profile with its own Postgres,
  Redis, network and init volume. The app no longer mounts the Docker socket;
  a dedicated sandbox broker is the only service that talks to the daemon. A
  live smoke test covers the SSH attack → event → alert/incident path, plus an
  outbox drain after a Brain outage.

### Changed

- Toolchain brought to Python 3.15.2, Java 25 (Temurin 25.0.5), Spring Boot
  4.1.2 and Node 26. The Redis serializer now uses Jackson 3; the Sigma and
  correlation loaders use pure-Python `ruamel.yaml` so Python 3.15 on Windows
  does not need MSVC. YARA remains explicitly fail-soft on Python 3.15 because
  `yara-python` has no CPython 3.15 wheel yet.
- README tagline and license section now describe the actual open-source
  positioning.
- The frontend no longer loads Google Fonts: typography uses system fonts, so
  the dashboard and the Kraken UI make no external request at runtime.
- `v4.1.0` is the next release. It is a hardening minor, not a new major; the
  version fields in the code stay at `4.0.0` until the release PR.

### Security

- Removed the unused `pymongo` and `motor` drivers from the Brain
  dependencies (AEGIS-LOGIC-008).
- Bumped PyJWT to `2.15.1` for the tracked advisories (AEGIS-LOGIC-009).
- NodeTrace no longer passes device secrets in `curl` arguments; headers use a
  `0600` config file and the body goes through stdin (AEGIS-SEC-011).
- OTA updates now require an Ed25519-signed manifest; the HMAC signed with the
  enrollment key was removed (AEGIS-SEC-002). The one-liner installer writes
  the single-use enrollment token to a `0600` file instead of the persistent
  environment and injects the manifest public key.
- Re-enrollment of an existing hostname now requires a token issued for that
  host; the static enrollment key only creates new agents. Agents send a
  machine-id, of which the Brain stores only the hash (AEGIS-SEC-001).
- `REMOVE_PERSISTENCE` deletes only the matching registry value instead of the
  whole Run key; Linux reports `unsupported` instead of a false `ok`
  (AEGIS-SEC-007).
- Other findings are documented in the handoff plan; this section lists only
  changes present on `dev`. They ship only after merge.

### Fixed

- A tab left open across a frontend rebuild no longer keeps failing to load
  lazy pages until a manual refresh: `vite:preloadError` triggers one guarded
  page reload, so the tab picks up the new chunk names automatically.

### Known limitations

- The 12 Playwright e2e tests and the opt-in Kraken vertical smoke pass
  manually against the live stack, but they are not a v4.1 CI gate; the CI
  runner is planned for 4.2. The two live detection batteries are also manual
  in 4.1.
- Release assets are checksummed with `SHA256SUMS.txt` and verified against
  `RELEASE_MANIFEST.json`. Cosign signing is a separate release step: a bundle
  without `SHA256SUMS.txt.sig` is checksummed, not a signed production
  artifact.

## [4.0.0] - 2026-09-21

### Added

- Windows kernel telemetry through ETW, ingested into the same enrichment
  pipeline as the process poll (`provenance=etw`, explicit degraded quality
  when the collector is missing); Linux keeps native eBPF.
- Sigma compiler with field modifiers and fail-loud exclusions, correlation
  windows, alert policy with trusted-signed suppression and triage muting.
- Telegram as a read-only remote control (`/status`, `/alerts`, `/help`) and
  severity-filtered notifications.
- One-line signed enrollment for Guard and NodeTrace, including Windows service
  and systemd registration, Java version verification, and honest failure
  reporting.
- `scripts/pack-artifacts.py` for the artifacts served by the Brain.
- `aegis.bat services` for one-command persistent agent installation.

### Fixed

- Release packaging copied the shaded Guard jar correctly and no longer
  attached an empty release.
- SBOM generation and NVD dependency-check retries were hardened.
- Heartbeat interval is read from the database; session re-login is safe.
- Guard dependency bumps clear the tracked HTTP client advisory.

### Security

- A live enrollment key was removed from `HEAD`; history rewrite is still
  planned separately.
- Service installs read the enrollment key from the environment instead of the
  repository.

### Release assets

`aegis-guard.jar`, `sbom.spdx.json`, `SHA256SUMS.txt`. Brain, Link, Frontend,
NodeTrace, the compose bundle and upgrade notes were **not** released; this is
tracked as AEGIS-REL-002.

## [3.0.0] - 2026-07-09

### Added

- Standalone NodeTrace and Guard builds (PyInstaller, Maven + jlink).
- Discovery Center: ping sweep, ARP, TCP scan, reverse DNS, OS guess, IP
  reputation, and agent status per host.
- Remote deployment through WinRM/SSH (later replaced by signed enrollment).

### Changed

- CI moved to GitLab only in this release; GitHub Actions was restored later.

### Fixed

- `curl_http` fallback when `curl.exe` fails in a PyInstaller bundle.
- Guard command polling handles a JSON `null` without error spam.
- Database pool recycling prevents connection exhaustion.
- Dashboard WebSocket defaults to the local host instead of a broken URL.

### Tests

Release notes report 166 tests passing.

## [2.0.0] - 2026-05-29

### Changed

- The Brain became a modular monolith, consolidating heuristics, AI, OSINT and
  VaultX domains while keeping the asynchronous pipeline.
- Guard and NodeTrace became the two supported agents.
- Shared API keys were replaced by per-agent enrollment and revocable
  credentials.
- VaultX introduced AES-256-GCM envelope encryption.
- The AI suite added prompt-injection protection and Redis-backed rate limits.
- CI/CD moved to GitLab in this release.

### Added

- Extended detection that correlates endpoint processes with OSINT and
  performance anomalies.
- Zero-trust ingestion through Aegis-Link and Redis before telemetry reaches
  the Brain.

## [1.0.0] - 2026-05-15

### Added

- Initial EDR stack: Guard (Java 21), Aegis-Link (Spring Boot), Brain
  (FastAPI), and a React dashboard.
- Heuristic detection for known attack tooling, double extensions, suspicious
  execution paths, encoded PowerShell, and privilege anomalies.
- Asynchronous Redis-backed ingestion, PostgreSQL persistence, Docker Compose
  deployment, and Windows/Linux installation scripts.

[4.3.0]: https://github.com/Terminalkid09/aegis-ecosystem/compare/v4.2.1...HEAD
[4.1.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v4.1.0
[4.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v4.0.0
[3.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v3.0.0
[2.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v2.0.0
[1.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v1.0.0
