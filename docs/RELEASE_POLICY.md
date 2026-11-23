# Release policy

Status: 2026-11-22. This policy applies to the Aegis Ecosystem server and
endpoint packages. It is deliberately conservative: a version that is not
maintained must not look maintained just because its artifact is still online.

## Supported lines

| Line | Status | What is maintained |
|---|---|---|
| `4.3.x` | **Current stable** | Security fixes, critical correctness fixes, packaging fixes and documentation corrections. |
| `4.2.x` | **Previous minor** | Security and critical correctness fixes only. No new features or non-essential packaging changes. |
| `4.1.x` and older | **End of life (EOL)** | Nothing. The published tags and artifacts remain immutable, but no fixes or compatibility guarantees are provided. |

When a new minor line is released, the current line becomes the previous minor
and the previous minor becomes EOL. For example, after `4.4.0` is published,
`4.4.x` is current, `4.3.x` receives maintenance fixes, and `4.2.x` is EOL. The
team may publish a security-only patch outside this cadence; that does not
extend support for an older line.

`4.3.0` is a controlled-pilot release, not production GA. The support table
describes maintenance intent, not a warranty or a certified production claim.

## Artifact retention

- Published Git tags and GitHub Releases are **immutable**. They are not
  deleted, moved or reused.
- Release assets that still exist remain downloadable. An old artifact is
  retained for reproducibility, not because it is supported.
- Windows and Linux assets for the same version are built from the same source
  commit and follow the same support line.
- The project does not promise that every historical version can be rebuilt
  from source. It does promise that a published artifact is not silently
  replaced with different bytes.

## Release publication

- The `v*` tag run is the only publication path. `ci.yml` builds the bundle and
  creates the release; `packaging.yml` adds the installable packages and their
  `.sha256` sidecars, so `ak update` and `--latest` resolve to real assets.
- The upload job refuses to overwrite an existing asset. That is what keeps a
  `v<version>` URL stable for every installed client.
- A tag build runs the production-signing jobs. Test-signed MSIs use an ephemeral
  certificate and are **not** attached: the job warns and skips them. Until the
  server MSI is produced with the operator's certificate, Windows releases carry
  no MSI and `ak update` fails closed instead of installing a test signature.

## `ak update` rules

`ak update` is an explicit operator action. It is not an unattended updater and
does not enable itself.

- `--latest` selects the latest **published, non-prerelease** GitHub release.
- `--version X.Y.Z` selects an explicit release. The version must have the
  matching artifact and `.sha256` sidecar; a missing checksum is a hard failure.
- The updater verifies the SHA-256 before invoking the platform installer.
- The updater preserves the existing FQDN, ACME email and dashboard port.
- A newer version is installed normally. A downgrade requires
  `--allow-downgrade` and a **verified database backup**. Database migrations
  are not automatically reversed.
- `--check` and `--dry-run` do not change the host.
- `--no-restart` updates the package without restarting the stack.
- Updating the CLI and updating the services are one operation because both are
  delivered by the same platform package; the post-install lifecycle rebuilds
  changed images on the next start.

## Upgrade and rollback boundary

- A server upgrade must be applied with the matching database backup available.
- Rolling back the package without restoring a compatible database is
  unsupported where the release contains a schema migration.
- Endpoint agent rollback remains outside the 4.3.0 contract. The server
  rollback boundary is the server package plus a database restore.
- A failed checksum or a failed installer leaves the previous package in place
  where the platform installer supports transactional rollback. The operator
  must verify `ak version`, `ak status` and the health endpoints after any
  update.

## Pre-releases

Release candidates and prerelease tags are never selected by `--latest`. They
may be installed explicitly with `--version` only when their artifacts and
checksums are published, and they carry no support commitment.
