# Aegis — 4.3 Live Validation Roadmap

Status: decision record, 2026-11-19, updated 2026-11-21. This document is the
English source of truth for the validation work kept **inside the 4.3.0 release
cycle**. The older Italian `docs/archive/ROADMAP.md` remains the long-term
product roadmap. AP-126/AP-127 are part of the 4.3 production gate. This
repository delivers the isolated harness and the labelled-corpus gate; running
an authorized real sample and measuring a real corpus require operator-provided
lab and corpus inputs, not fabricated results.

## 4.3 enterprise/Kraken addendum (2026-11-21)

The user expanded the 4.3 scope: signed endpoint packages, realistic Kraken
engines, configurable Docker limits and a roadmap for Lab/self-improvement.
This addendum is the working checklist; none of it changes the `NOT RELEASED`
status until the branch PRs are green and the two branches are merged in `dev`.

### Kraken — real engines delivered on `feat/4.3-kraken`

| Protocol | Engine | What it now does | Remaining gap |
|---|---|---|---|
| SSH | `asyncssh` | Real SSH auth, host key, sandbox-backed interactive shell, realistic fallback shell. | Credential policy is intentionally permissive; no Cowrie integration. |
| HTTP | asyncio HTTP | vhosts (`portal`, OWA, RDWeb), Apache/nginx-style statuses, recon paths, request body capture. | No TLS terminator and no dynamic web app; static profiles only. |
| FTP | `pyftpdlib 2.2.0` | Real login, PASV, LIST/RETR/STOR/DELE/MKD, decoy filesystem, upload SHA-256. | Passive advertise host must be set correctly by the operator. |
| Telnet | asyncio + sandbox | Real login and interactive shell; realistic fallback when the broker is down. | Telnet negotiation is deliberately minimal. |
| SMB | `impacket 0.13.1` | SMB2 share, auth, list/read/write, NetNTLMv2 capture with `outputToJohnFormat`. | SMB signing/relay are not implemented by design; legacy raw engine remains available with `KRAKEN_SMB_ENGINE=raw`. |
| RDP | `xrdp` + XFCE | Real RDP endpoint with three weak decoy accounts; PAM/xrdp authentication logs are forwarded to the signed Kraken ingest path by `rdp/log_shipper.py`. | Shipped in this branch; the unit parser is tested in CI. |

Exposure is still explicit: the base compose keeps the listeners internal; the
overlay maps standard public ports. SMB/RDP use unprivileged container ports
(`4445`/`33890`) internally because the sensor process is non-root.

### Enterprise packaging — `feat/4.3-packaging`

- **Delivered in 4.3:** reproducible MSI, `.deb`, RPM and OpenWrt `ipk` build
  paths; provider-agnostic Authenticode signing via PFX or certificate
  thumbprint; production GPG mode; cosign keyless signing for `SHA256SUMS`;
  clean-host install/uninstall checks in CI; and test signing for CI only.
- **Operator inputs still required:** the real Authenticode certificate/key,
  the real GPG/cosign key and an MDM/Intune/GPO tenant for a tenant-specific
  validation. The code paths are implemented; a test signature is never
  presented as a production signature.
- The MSI is a deployment mechanism, not an enrollment secret store: the token
  is provisioned by MDM/GPO or the documented manual fallback.

### Docker limits

All long-running services accept `AEGIS_*_MEM_LIMIT`, `AEGIS_*_CPUS` and
`AEGIS_*_PIDS`. `scripts/check_compose_limits.py` proves the overrides reach the
rendered compose model; `scripts/load_limits.sh` wraps `pilot_soak.py` and
captures `docker stats` before/after. `mem_limit`/`cpus` are Compose v2 fields,
not Swarm `deploy.resources`; `pids_limit` is Linux-only.

### Lab and self-improvement — 4.3 scope with explicit remaining work

**Advanced Kraken lab:** simulated topologies and subnets, multi-host decoys,
scenario/assertion engine, per-sensor port profiles, source-IP preservation on
Linux, controlled file drops and a restore/snapshot lifecycle. These are
required before calling Kraken a lab product; the current branch provides real
protocol engines, not a range orchestrator.

**Self-improvement:** signed model/rule updates, offline evaluation, shadow and
canary rollout, automatic rollback, drift/FP monitoring and human approval.
Auto-modification of detection logic and autonomous response remain explicitly
out of scope. No self-improvement component is implemented in 4.3.

**AP-126 / AP-127:** part of the 4.3 production gate. The repository now
contains a bounded sandbox harness (read-only, no network, kill switch) and a
labelled-corpus gate with recall/FPR and per-host/day metrics. Real malware
detonation still needs an authorized sample plus snapshot/restore lab; a
production FP/FN rate still needs a real labelled corpus. The 4.3 fixture run
proves the harness, not production quality.

## Decision

- **4.3.0** is a production-capable release after the six gates and the
  production packaging gates pass: static analysis, controlled detonation
  integration, local/Garage object storage, the at-least-once command path and
  installable signed-package paths. The external certificate, MDM tenant and
  authorized lab/corpus remain operator inputs, not missing code.
- The release is cut **directly as `v4.3.0`**. There is no `4.3.0-rc1` tag and
  no separate RC publication.
- The six gates (50k Link load, crash/restart, release bundle, server upgrade,
  hosted CI at tag and clean install) are part of 4.3. The cycle is longer to
  collect live evidence before the tag.
- **Agent rollback is out of scope for 4.3.0.** The user decision is explicit:
  no rollback to the previous Guard/NodeTrace agents. The server rollback and
  database restore boundary remain documented.
- **4.3.0 does not claim certified real-malware detonation.** The integration
  is exercised with a controlled HTTP detonator; no malware is executed on the
  host or by the web process.
- Real detonation and adversarial quality evidence are part of the **4.3
  production gate**, but require the authorized external lab and corpus. The
  shipped harness must not be presented as a completed malware certification.
- **AWS is optional.** A customer may run local storage, Garage/Ceph on their
  own server, or AWS S3. No cloud dependency is required for 4.3.
- CI runs on `dev`, `main`, `feat/**` and pull requests, plus the release tag;
  only the `release` publishing job is tag-only. This makes the release gate
  visible before an immutable tag without pretending a branch run is Gate 5.

## Phase 1 — 4.3.0 release (inside 4.3)

**Goal:** a coherent, honest controlled-pilot release with live evidence before
the tag.

Required evidence:

- Link HTTP → Redis → Brain → Postgres live path;
- atomic Link check+push, no `202` when neither Redis nor spool accepted;
- Link 50k boundary: 50,000 accepted, one 429, Redis depth at the cap, no 5xx;
- command claim/ack/requeue/DLQ on Brain and Link;
- restart after a claim without ack, with the same `delivery_id` and attempt 2;
- UI / Playwright and Go tests green;
- static file analysis, job recovery, deletion verification;
- optional S3 adapter tested against an S3-compatible server;
- release bundle smoke test, server upgrade, hosted CI at tag and clean
  install (the six gates in `docs/RELEASE_GATE_4.3.md`);
- diagrams and docs in English for the public-facing material.

Out of scope for the 4.3.0 claim:

- real malware execution without the authorized external lab (AP-126 harness
  is shipped; live malware is not);
- certified sandbox isolation beyond the tested bounded policy;
- AWS certification;
- production FP/FN rates without the real labelled corpus (AP-127 gate is
  shipped);
- agent rollback to the previous Java/Python runtimes;
- firewall and DNS policy features (4.5 Network Visibility).

## Phase 2 — 4.3.x live validation (after 4.3.0)

**Goal:** test the paths that only a real lab can validate. This is part of the
4.3 production evidence cycle when the authorized lab/corpus is available; it
is not a substitute for the six release gates above.

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
- Kraken advanced-lab expansion: simulated topologies/subnets, multi-host
  decoys, scenario assertions, source-IP preservation on Linux and a
  signed xrdp log shipper; the real protocol engines are now in 4.3;
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
- “synthetic detection baseline, not a production FP/FN rate”;
- “controlled-pilot release, not production GA”.

Not allowed:

- “real malware detonation certified”;
- “AWS tested” or “MinIO tested”;
- “exactly-once”;
- “production-ready detection quality”;
- “agent rollback tested” (it is outside 4.3.0).

## References

- `docs/RELEASE_GATE_4.3.md`
- `docs/benchmarks/4.3/detection-quality.md`
- `docs/archive/ARCHITECTURE_AEGIS_KRAKEN.md`
- AP-126, AP-127 in YouTrack
