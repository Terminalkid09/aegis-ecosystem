# Release audit — Aegis Ecosystem

Status: 2026-11-16. This document audits the tags that already exist, including
the completed `v4.1.0` release. It does not move history.

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

## Current version fields

These are the release version fields for `v4.1.0`.

| Component | File | Current |
|---|---|---|
| Brain API | `aegis-brain/app/core/config.py` | `4.1.0` |
| Frontend | `frontend/package.json` | `4.1.0` |
| Guard | `aegis-guard/pom.xml` | `4.1.0` |
| NodeTrace | `NodeTrace/agents/python/agent.py` | `4.1.0` |
| OCSF agent metadata | `aegis-brain/app/services/ocsf.py` | `4.1.0` |
| Artifact packer | `scripts/pack-artifacts.py` | `v4.1.0` |
