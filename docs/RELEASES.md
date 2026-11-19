# Release audit — Aegis Ecosystem

Status: 2026-11-19. This document audits the tags that already exist, including
the completed `v4.1.0` release. It does not move history. The current release
being prepared is `v4.3.0`; it is not tagged or published yet.

## Published tags are immutable

`v1.0.0`, `v2.0.0`, `v3.0.0`, `v4.0.0` and `v4.1.0` exist on `origin` and have
GitHub Releases. They are historical facts. Do not delete them, force-move them, or
reuse their numbers. A published version is a promise, even when the release
behind it was incomplete.

The local tag `v4.0.0` points to `de52206` ("Merge dev"); the remote tag and
the GitHub Release point to `38e245f` ("Merge pull request #8"). The remote is
canonical. This is a local staleness problem, not permission to rewrite the
remote. Align it only with an explicit fetch after approval:

```bash
git fetch --tags --force
```

Do not run `git tag -d`, `git tag -f` or `git push --force --tags` on these
tags.

## Tag inventory

| Tag | Published | Remote commit | Local commit | GitHub Release | Assets |
|---|---|---|---|---|---|
| `v1.0.0` | 2026-05-15 | `0fb0f9d` | `0fb0f9d` | yes | none |
| `v2.0.0` | 2026-05-29 | `f464e98` | `f464e98` | yes | none |
| `v3.0.0` | 2026-07-09 | `058dea5` | `058dea5` | yes | none |
| `v4.0.0` | 2026-09-21 | `38e245f` | `de52206` | yes | `aegis-guard.jar`, `sbom.spdx.json`, `SHA256SUMS.txt` |
| `v4.1.0` | 2026-11-16 | `17c499f` | `17c499f` | yes | 24 assets: Brain/Link/Frontend/Guard/NodeTrace, compose, SBOM, source, seven images, manifests/checksums |
| `v4.2.1` | 2026-11-18 | `1de7443` | `1de7443` | yes | 4.2 maintenance release; NodeTrace spec tracked |
| `v4.3.0` | not cut | — | — | no | release prepared; hosted tag CI still required |

The first four are lightweight tags; `v4.1.0` is annotated. `v4.0.0` and
`v4.1.0` are the only ones whose code version matches the tag: `aegis-brain`
and `frontend` declared `4.0.0`/`4.1.0`, and Guard declared the same. At
`v1.0.0`–`v3.0.0`, the frontend still declared `0.1.0` and Guard `1.0.0`, so
the tag numbers were batch labels rather than a coherent product version.

## What the old releases actually contain

`v4.0.0` attaches only the Guard jar, the SBOM and the checksum file. It does
not attach Brain, Link, Frontend, NodeTrace, a compose bundle, an upgrade guide
or a changelog. That is AEGIS-REL-002, and it is the reason the next release
cannot be “just another tag”.

The first three releases have no assets at all. Their value is provenance:
they mark the initial EDR framework, the modular-monolith rewrite, and the
standalone-agent/discovery release.

## Why the numbers are not lowered

Lowering `v4.0.0` to `v2.0.0`, or deleting the old tags to start again, would
break release links, clones and any external reference. It would also make the
history less honest, not more. The problem is not that the number is high; it is
that the number was raised for batches and the release was incomplete.

The safe correction is:

1. Keep `v1.0.0`–`v4.0.0` exactly where they are.
2. Stop incrementing MAJOR for batches.
3. Ship the next release as `v4.1.0`, a hardening minor, only when it is a
   complete release.
4. If a true product reset is ever needed, use a written decision and a new
   namespace. Do not rewrite published tags.

## Version mapping

| Tag | Meaning | Status |
|---|---|---|
| `v1.0.0` | Initial EDR framework | historical |
| `v2.0.0` | Modular-monolith Brain, unified agents, VaultX, AI suite | historical |
| `v3.0.0` | Standalone agents and Discovery Center | historical |
| `v4.0.0` | EDR + SIEM platform, ETW, Sigma, Telegram, signed enrollment | historical; last batch tag |
| `v4.1.0` | Foundation + complete Kraken vertical: blocking fixes, CI green, compose/outbox/UI/unified view, complete release | released 2026-11-16; complete |
| `v4.2.1` | Kraken outbox/lab hardening and 4.2 maintenance | released 2026-11-18 |
| `v4.3.0` | Unified Go agent, at-least-once commands, 50k Link and release gates | prepared 2026-11-19; tag not cut |

`v4.1.0` is a **minor** because it fixes and hardens existing contracts. The
removal of the disabled-by-default `script` playbook action will be documented
in `UPGRADING.md` in the release PR; it does not justify a major. A future `v5.0.0` is reserved for
an incompatible public contract change or a platform milestone that actually
requires it. It is not a reward for finishing a batch.

## Release integrity gate

A release is a vertical slice, not a backend milestone with the UI promised for
the next version. Before tagging, the release must have:

- the user-visible path complete: API + UI + documentation + test;
- a capability labelled **experimental/opt-in** when it is not complete, and no
  release note that calls it “integrated”;
- a smoke test executed from the downloaded release artifact, not from the
  working tree;
- no known half-feature whose missing half is already scheduled for the next
  release train.

Kraken is the current example. `v4.1.0` is the release in which the complete
vertical ships: Kraken in the compose profile, signed ingest with outbox and
retry, reachable Kraken UI, read-only Aegis view and an end-to-end smoke test.
It must **not** be tagged with the service merely “startable” and the UI
promised for later. Expansion work (new sensors, campaigns, Lab, unified
timeline, ATT&CK) belongs to `v4.2.0` and later, and must be described as
expansion — not as the missing half of 4.1.

## Checklist before `v4.1.0`

- [x] Gate 0 complete: license, security policy, privacy documents, trademark
      check.
- [x] AEGIS-REL-002 assets: Brain, Link, Frontend, NodeTrace, Guard, compose
      bundle (including the `kraken` profile), CycloneDX SBOM, checksums,
      changelog, upgrade notes. The seven release images are shipped as
      `aegis-images.tar.gz`; if the compressed archive exceeds the 1.9 GB
      safety threshold it is split into `aegis-images.tar.gz.part-*` and must
      be reassembled with `cat` before `docker load`. **Cosign signature is
      still not produced; the release is checksummed, not signed.**
- [x] Kraken vertical complete: outbox/retry, signed ingest, reachable UI,
      read-only Aegis view, end-to-end smoke test from the downloaded bundle.
- [x] Release bundle built from the tag commit and verified with
      `release-smoke.py` from a fresh download: 22 manifest files;
      `nodetrace.zip` excludes `token.json`, `device.key`, `device.crt` and
      `nodetrace.pid`.
- [x] All version fields updated together: Brain `APP_VERSION`, frontend
      `package.json`, Guard `pom.xml`, NodeTrace `AGENT_VERSION`, OCSF agent
      version, `scripts/pack-artifacts.py`.
- [x] `CHANGELOG.md` and `UPGRADING.md` updated in the release PR.
- [x] CI green on the release commit: tag run `43916328707`, all jobs green.
- [x] Annotated tag from `main`: `git tag -a v4.1.0 -m "Aegis 4.1.0"` at
      `17c499f`.
- [x] GitHub Release built from the tag, with assets and smoke test from the
      downloaded artifacts, not from the repository:
      <https://github.com/Terminalkid09/aegis-ecosystem/releases/tag/v4.1.0>.
- [x] No force-push, no tag rewrite, no `latest` tag.

## v4.1.0 release candidate (2026-11-16)

Measured on commit `4ac83b5` before the release merge:

- Brain **823 passed, 3 skipped**; Kraken **130 passed**; Guard **140**; Link
  **17**; NodeTrace **58 passed, 2 skipped**; frontend build OK and lint
  **0 errors / 25 warnings**; Playwright pages **4 passed** and Kraken
  vertical **2 passed**; `scripts/api_smoke.py` **ALL PASS**.
- Security: bandit Brain **0 High**, Kraken **0 High** (one Medium B108 on the
  container tmpfs path); `pip-audit` Brain and Kraken **0**; `npm audit` **0
  vulnerabilities**; compose and Caddy valid; SSO exchange 200 / replay 401;
  outbox `pending 0` with deliveries `sent`.
- Release bundle: **21 files**, `release-smoke.py` **OK** from a copied
  directory; `nodetrace.zip` has 39 entries and no `token.json`, `device.key`,
  `device.crt` or `nodetrace.pid`; Guard jar is 4.1.0.
- Still open at this commit: CI on the release commit, annotated tag and GitHub
  Release. Cosign signing is not produced; the bundle is checksummed, not
  signed.

## v4.1.0 final release verification (2026-11-16)

- Annotated tag `v4.1.0` at `17c499f`; tag CI run `43916328707` green,
  including `Build & Test` (NVD audit) and `Release Artifacts`.
- GitHub Release: 24 assets. The 22 manifest entries are the 20 core/SBOM
  assets plus `nodetrace.zip` and `aegis-images.tar.gz`; `RELEASE_MANIFEST.json`
  and `SHA256SUMS.txt` complete the 24.
- Fresh-download smoke: `release-smoke.py` **OK, 22 files**; every
  `sha256sum -c` entry **OK**; `nodetrace.zip` **39 entries**, no
  `token.json`, `device.key`, `device.crt` or `nodetrace.pid`; image archive
  `gzip -t` **OK**; source tar contains `.env.example` and the smoke script.
- GitHub normalizes release asset names that begin with a dot: the uploaded
  asset is `default.env.example`, and the operator must rename it to
  `.env.example` before running the smoke test. This is documented in the
  Release notes and is a release-pipeline defect to remove in 4.2.
- Honest limitations: no cosign signature; no per-image SBOM (the release has
  one CycloneDX SBOM for the repository); the Windows NodeTrace zip is built
  locally and attached to the release because the Linux release job cannot
  produce it; Playwright and live detection batteries remain manual gates.

## 4.2 release candidate verification (2026-11-18)

Status: PR #13 was merged into `main` at `5c89d41`. The `v4.2.0` tag was created there, but its tag workflow (`44351348039`) failed before publishing: `nodetrace-agent.spec` was ignored by `*.spec` and absent from the tag, so the Windows package job could not build. **No GitHub Release exists for `v4.2.0`.** `v4.2.1` tracks the spec, runs the NodeTrace Windows package job on pull requests, and is the first complete 4.2 release. The 4.2.0 code passed hosted run `44342912879`, including `Compose E2E Gate` (Playwright **13/13**), and the merge commit passed main run `44349513947`. Local verification on 2026-11-18: Brain **853 passed, 3 skipped** against a disposable PostgreSQL test database, Kraken **150 passed**, Playwright **13/13**, `api_smoke.py` **ALL PASS** (21 checks), frontend lint **0 errors / 26 warnings**, `npm audit --omit=dev` **0 vulnerabilities**, build **OK**, root and Kraken Compose stack **OK**, **aegis-kraken-sensors healthy**. The v4.2.1 tag and release are the remaining gate.

**Load gate — met locally; hosted CI does not measure throughput.** On the default **2-worker**
stack, `/telemetry/report` with unique, committed events reached **289.35 rps
through Caddy/TLS** (1.500/1.500 `200`, p95 159.9 ms, p99 188.8 ms) and
**247.76 rps direct** (3.000/3.000 `200`, 3.008 DB rows, p95 194.4 ms). The
20-agent cold proof burst reached **341.16 rps** (p95 52.3 ms) and 100 warm
events reached **301.16 rps** (p95 91.5 ms); no read timeouts. Legacy agents
take 79.4 ms on first contact and 38.7 ms after backfill. The old **96–111.58
rps** was an 8-worker measurement, not the default Compose path, and is
superseded; `synchronous_commit` remains `on`. Hosted CI/E2E passed on
`00eb030`; merge, tag and release await explicit approval.

- `npm audit --omit=dev` is clean (**0**), and CI blocks the runtime tree. The
  development tree still reports **5 high `picomatch` advisories** through
  Vite/fdir/tinyglobby; no patched release exists, and these tools are not
  shipped in the runtime image. CI reports the dev audit without blocking.
- `release-bundle.py` emits `env.example`, not `.env.example`, and has a focused
  contract test for the final asset name and the NodeTrace identity exclusion.
- The tag workflow has a Windows `nodetrace_windows` job that builds the
  PyInstaller package and uploads it as an artifact; `release` consumes it.
- The tag workflow builds all seven release images, generates a CycloneDX SBOM
  for each with pinned Syft, records the names in `RELEASE_MANIFEST.json`, and
  includes them in the bundle.
- `release-smoke.py` now requires `env.example`, `frontend.zip`,
  `RELEASE_SIGNING.md`, the source archive and the core assets; the tag job
  runs it with `--require-nodetrace --require-image-sboms` before publishing.
- `docs/RELEASE_SIGNING.md` records that 4.2 remains **checksummed, not
  signed**, and that a GitHub build-provenance attestation is produced for the
  release assets. Provenance is verifiable; it is not a cosign signature.
- Local bundle verification: `v4.2.0-rc1` produced **29 files**;
  `release-smoke.py` **OK**; `env.example` present and no `.env.example`;
  seven fixture image SBOMs recorded; `nodetrace.zip` **39 entries**, no
  `token.json`, `device.key`, `device.crt` or `nodetrace.pid`.
- Real Compose E2E on the running stack: Playwright **13/13 passed**
  (including setup, pages, session and the Kraken vertical) after a fresh seeded
  event; `scripts/api_smoke.py` **ALL PASS** (21 checks). The first Kraken run
  failed because the existing `203.0.113.77` event was outside the 24-hour
  window; the fix is the deterministic `services/kraken/scripts/seed_e2e.py`,
  not a product change.
- The `aegis-kraken-sensors` container now has a localhost-only HTTP health
  listener on port 8000. It reports `healthy` without probing a honeypot port,
  so the healthcheck cannot create fake attacks or SIEM events.
- Hosted CI run `44342912879` and the Compose E2E gate passed on the 4.2 code;
  PR #13 merged at `5c89d41`. The first `v4.2.0` tag stopped in the NodeTrace
  Windows package because `nodetrace-agent.spec` was ignored; `v4.2.1` tracks
  the spec and runs that package job on pull requests.
- Added after the pipeline work: timeline, deception rules/correlation,
  campaigns/fleet/topology/Lab UI, SMB/RDP sensors, ATT&CK coverage, governed
  suppressions, mTLS fingerprint enforcement and asynchronous static file
  analysis. These are implementation candidates, not release verification.

## v4.3.0 release preparation (2026-11-19)

Direct `v4.3.0` release, no `4.3.0-rc1`. The locally executable gates are green:
27 Link tests, 8 Brain command-queue tests, the 50k Link live cap, process-level
command restart, `queued — not executed` UI visibility, a 28-file bundle with the Go agent and
checksums, a clean install from the extracted bundle with API smoke **21/21**,
and a 4.2.1 server upgrade preserving **68 agents / 321 alerts** with smoke
**21/21**. The annotated tag, hosted tag workflow, downloaded-asset verification
and publication remain the external release step. The release is checksummed,
not cosign-signed; see `docs/RELEASE_SIGNING.md`.

## Current version fields

These are the release version fields for the `v4.3.0` release.

| Component | File | Current |
|---|---|---|
| Brain API | `aegis-brain/app/core/config.py` | `4.3.0` |
| Frontend | `frontend/package.json` | `4.3.0` |
| Unified Go agent | `aegis-agent/internal/config/config.go` | `4.3.0` |
| Guard legacy | `aegis-guard/pom.xml` | `4.3.0` |
| NodeTrace legacy | `NodeTrace/agents/python/agent.py` | `4.3.0` |
| OCSF agent metadata | `aegis-brain/app/services/ocsf.py` | `4.3.0` |
| Artifact packer | `scripts/pack-artifacts.py` | `v4.3.0` |
