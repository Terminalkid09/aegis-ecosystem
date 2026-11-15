# Changelog

All notable changes to Aegis Ecosystem are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Semantic Versioning applies to releases after `v4.0.0`. The older tags
`v1.0.0`–`v4.0.0` were batch labels, not complete SemVer releases; they remain
published and are not rewritten. See [docs/RELEASES.md](docs/RELEASES.md) for
the tag audit and the release policy.

> A published version is immutable. The next release is `v4.1.0`; it is cut
> only after Gate 0 and AEGIS-REL-002 are complete.

## [Unreleased]

> Changes on `dev`. Not released.

### Added

- Gate 0 licensing groundwork: `LICENSE` (AGPL-3.0-only), `NOTICE`,
  `TRADEMARK.md`, `SECURITY.md`, `CONTRIBUTING.md`, and the
  `THIRD_PARTY_NOTICES.md` placeholder.
- `docs/PLAN_AEGIS_KRAKEN_HANDOFF.md` v2.5: D2 agent vs network sensor, D16
  portfolio-first with no fixed date, PR/merge/release flow, and the published
  tag policy.
- `docs/RELEASES.md`: audit of the published tags and the release checklist.
- `docs/youtrack_tickets.csv` and `scripts/youtrack_import.py`: import path for
  the findings and roadmap work packages.
- `scripts/test-restore.sh` and the nightly `Backup Restore Check` workflow:
  an encrypted backup/restore round-trip creates disposable databases and
  verifies a probe row instead of trusting the restore path by inspection.

### Changed

- Toolchain brought to Python 3.15.2, Java 25 (Temurin 25.0.5), Spring Boot
  4.1.2 and Node 26. The Redis serializer now uses Jackson 3; the Sigma and
  correlation loaders use pure-Python `ruamel.yaml` so Python 3.15 on Windows
  does not need MSVC. YARA remains explicitly fail-soft on Python 3.15 because
  `yara-python` has no CPython 3.15 wheel yet.
- README tagline and license section now describe the actual open-source
  positioning.
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

### Known limitations

- The 12 Playwright e2e tests pass manually against the live stack, but they
  are not a v4.1 CI gate; the CI runner is planned for 4.2. The two live
  detection batteries are also manual in 4.1.
- The local release dry-run verifies checksums and the manifest. It does not
  produce a cosign signature, and the GitHub release job has not been run.

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

[Unreleased]: https://github.com/Terminalkid09/aegis-ecosystem/compare/v4.0.0...HEAD
[4.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v4.0.0
[3.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v3.0.0
[2.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v2.0.0
[1.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v1.0.0
