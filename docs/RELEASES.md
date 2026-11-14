# Release audit — Aegis Ecosystem

Status: 2026-11-14. This document audits the tags that already exist. It is not
a release and it does not move history.

## Published tags are immutable

`v1.0.0`, `v2.0.0`, `v3.0.0` and `v4.0.0` exist on `origin` and have GitHub
Releases. They are historical facts. Do not delete them, force-move them, or
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

All four are lightweight tags. `v4.0.0` is the only one whose code version
matches the tag: `aegis-brain` and `frontend` declared `4.0.0`, and Guard
declared `4.0.0`. At `v1.0.0`–`v3.0.0`, the frontend still declared `0.1.0`
and Guard `1.0.0`, so the tag numbers were batch labels rather than a coherent
product version.

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
| `v4.1.0` | Foundation: blocking fixes, CI green, Kraken starts safely, complete release | next; not tagged |

`v4.1.0` is a **minor** because it fixes and hardens existing contracts. The
removal of the disabled-by-default `script` playbook action will be documented
in `UPGRADING.md` in the release PR; it does not justify a major. A future `v5.0.0` is reserved for
an incompatible public contract change or a platform milestone that actually
requires it. It is not a reward for finishing a batch.

## Checklist before `v4.1.0`

- [ ] Gate 0 complete: license, security policy, privacy documents, trademark
      check.
- [ ] AEGIS-REL-002 complete: Brain, Link, Frontend, NodeTrace, Guard, compose
      bundle, per-component SBOM, checksums, signature, changelog, upgrade
      notes.
- [ ] All version fields updated together: Brain `APP_VERSION`, frontend
      `package.json`, Guard `pom.xml`, NodeTrace `AGENT_VERSION`, OCSF agent
      version, `scripts/pack-artifacts.py`.
- [ ] `CHANGELOG.md` and `UPGRADING.md` updated in the release PR.
- [ ] CI green on the release commit.
- [ ] Annotated tag from `main`: `git tag -a v4.1.0 -m "Aegis 4.1.0"`.
- [ ] GitHub Release built from the tag, with assets and smoke test from the
      downloaded artifacts, not from the repository.
- [ ] No force-push, no tag rewrite, no `latest` tag.

## Current version fields

These stay at `4.0.0` until the release PR. Do not bump them by hand in a
feature PR.

| Component | File | Current |
|---|---|---|
| Brain API | `aegis-brain/app/core/config.py` | `4.0.0` |
| Frontend | `frontend/package.json` | `4.0.0` |
| Guard | `aegis-guard/pom.xml` | `4.0.0` |
| NodeTrace | `NodeTrace/agents/python/agent.py` | `4.0.0` |
| OCSF agent metadata | `aegis-brain/app/services/ocsf.py` | `4.0.0` |
| Artifact packer | `scripts/pack-artifacts.py` | `v4.0.0` |
