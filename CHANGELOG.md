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

## [4.3.0] - 2026-11-19

### Aegis Agent 4.3.0 — parità funzionale NodeTrace e Guard

**Stato: release 4.3.0 per pilot controllati.** Il runtime Go e il profilo
`unified` sono verificati contro il Brain reale; la release non è production GA
e non dichiara la certificazione malware. Guard Java e NodeTrace Python restano
disponibili come runtime legacy durante la migrazione. Il rollback degli agenti
legacy non è un requisito della 4.3.0 ed è esplicitamente fuori perimetro.

NodeTrace (`sensor`) è stato verificato con la suite Python (82 test, 2 skip) e
con 84 funzioni di test Go su tutti i package. Il live test del binario copre
enroll, CSR, `token.json`, heartbeat, `/update`, comandi, ack, scan e header
`X-Client-Cert-Hash`; è stato eseguito sia con Brain finto sia contro il Brain
reale locale, con telemetria persistita in PostgreSQL.

Guard (`endpoint`) è stato portato per capacità, non come traduzione meccanica
dei 140 JUnit: `secret.json`/`agent_id`, enrollment `/enroll/enroll`, outbox
batch 25/500 ms con buffer 2.000, spool AES-256-GCM 50 MB con quarantena dei
file corrotti, FIM fsnotify, YARA CLI fail-closed, consumer ETW, monitor
processi con PID+start time, registry/servizi/persistenza/Defender/Authenticode
e le 14 azioni (kill, kill tree, block IP e temporaneo, quarantine, remove
persistence, DNS sinkhole, collect IOC, verify, isolate/deisolate, FIM, YARA,
update delegato). Il live test del binario copre identità, heartbeat/metriche,
comandi, ack e header `X-Client-Cert-Hash`; sul Brain reale il profilo endpoint
ha riportato FIM e response actions attivi, con ETW/YARA dichiarati non
disponibili su questo host.

Il profilo `unified` usa una sola identità Guard e un solo outbox, ma avvia
anche i collector sensor. Il Brain/UI lo accettano in enrollment, token di
deploy, job, OTA, Discovery e telemetria recente. Il primo avvio con token
monouso è stato provato contro il Brain reale: il token è stato consumato e
l'agente ha inviato telemetria. Restano aperti l'artefatto `unified-latest.zip`,
servizio/installer e rollback.

Evidenza eseguita il 2026-11-18 (fake) e il 2026-11-19 (stack reale):

| Gate | Risultato |
|---|---|
| `go test ./... -count=1` | 84 funzioni di test Go, tutti i package verdi |
| `go vet ./...` | verde |
| build Go Windows e Linux | verde, Go 1.27.4 |
| `mvn test` Guard Java | 140 test JUnit, 0 failure/error (Temurin 25.0.5.8) |
| NodeTrace Python | 82 test, 0 failure, 2 skip |
| live sensor/Guard con Brain finto | verdi; contratto di rete e comandi osservato |
| live sensor/endpoint/unified con Brain reale | verdi; righe telemetria 1/18/17, capabilities popolate |
| primo avvio unified con token monouso | token consumato, agent_type=unified, telemetria presente |
| deploy API unified | token 200, install.ps1/sh 200, job `manual_required`; SSH/WinRM 501 |
| A/B locale 2×8 s | NodeTrace 27.28 MB RSS vs Go sensor 18.43 MB; Guard Java 126.45 MB vs Go endpoint 18.77 MB |

Il benchmark è in `docs/BENCHMARK.md` e i dati grezzi in
`docs/benchmarks/4.3/agents-ab.json`. È una misura di footprint e startup su
Brain finto, non di ingestione PostgreSQL, mTLS/Caddy o flotta. Il vantaggio
misurato è la riduzione di RSS e artefatto; la CPU dell'endpoint Go è
comparabile a Java e non viene dichiarata più bassa. Durante la misura è stata
corretta una regressione reale del polling Windows (WMI/Authenticode per tutti
i processi ogni secondo), che saturava un core.

**Perimetro dichiarato:** artefatto unificato e packaging firmato MSI/deb/rpm,
servizio nativo e rollback Java/JRE/Python su host reale non sono parte della
4.3.0; sono lavoro successivo. Lo smoke contro il Brain reale è reale, ma non è
un test di flotta né di servizio installato. La 4.3.0 è una release per pilot
controllati, non una sostituzione production-grade dei due agenti legacy.

**Evidenza di release:** clean install isolata da sorgente senza artefatti
(`aegis-clean43`) con volumi nuovi, bootstrap admin, enrollment reale,
heartbeat, evento agente, alert Sigma `T1110.001`, frontend e Link health;
`api_smoke.py` **21/21 ALL PASS**. Il 50k Link, il restart del consumer comandi
e i bundle locali restano registrati in `docs/RELEASE_GATE_4.3.md`.

### Changed

- Toolchain Go portata a **1.27.4** (ultima stabile, inclusi i fix di sicurezza
  del 2 novembre 2026) in `aegis-agent/go.mod`, nel piano 4.3 e nella CI, che ora
  esegue `go test`, `go vet` e build del binario su Ubuntu e Windows. La macchina
  di sviluppo è stata portata da Go 1.26.5 a 1.27.4 tramite il pacchetto ufficiale;
  `go version` e `go env GOROOT` ora puntano alla nuova installazione.

### Added

- Test di integrazione live del sensor Go con Brain finto: enrollment, CSR
firmata da una CA di test, salvataggio identità, heartbeat/telemetria,
comandi batch, ack, scan Discovery e verifica dell'header `X-Client-Cert-Hash`.
- Live reale dei profili `sensor`, `endpoint` e `unified` contro il Brain
  locale: `scripts/live_agent_profiles.py`; primo avvio unified con token
  monouso e install.ps1/install.sh generati e verificati sintatticamente.
- Base del profilo `endpoint` Guard: `secret.json`/`agent_id`, enrollment
  `aegis-guard`, report legacy e layer di validazione comandi; test di
  integrazione con Brain finto e test sulle funzioni pure.

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
- `docs/PLAN_AEGIS_KRAKEN_HANDOFF.md` v2.7: the 4.1 scope is the complete
  Kraken vertical (compose, signed ingest with outbox/retry, UI, read-only
  Aegis view, end-to-end smoke test); new sensors, campaigns, Lab and unified
  timeline move to 4.2+.
- `docs/RELEASES.md`: audit of the published tags, the release checklist and
  the release-integrity gate: no user-visible capability is called integrated
  until API, UI, docs and tests ship together. The gate now names the complete
  Kraken vertical as a 4.1 requirement.
- `docs/ROADMAP.md`: explicit OSINT/SentinelX and deploy/fleet
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

[Unreleased]: https://github.com/Terminalkid09/aegis-ecosystem/compare/v4.2.1...HEAD
[4.1.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v4.1.0
[4.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v4.0.0
[3.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v3.0.0
[2.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v2.0.0
[1.0.0]: https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v1.0.0
