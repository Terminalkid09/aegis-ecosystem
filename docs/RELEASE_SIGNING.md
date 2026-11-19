# Release signing decision — 4.3.0

Status: 2026-11-19.

## Decision

`v4.3.0` remains **checksummed, not cosign-signed**. This is an explicit
limitation, not a claim that the release is signed. `SHA256SUMS.txt` and
`RELEASE_MANIFEST.json` protect against corruption in transit and let a
downloader verify the exact bytes; they do not authenticate the publisher.

The GitHub tag workflow produces a build-provenance attestation. That binds the
assets to the repository, commit and workflow run, but it is not a human
publisher signature.

## Why

Keyless cosign needs a working OIDC identity, a pinned installer and a
verification path in the release smoke test. Adding only the signing step
would produce a signature that nobody verifies, which is worse than an honest
unsigned release. The clean-install gate and the checksummed bundle are the
4.3.0 release-integrity priorities.

## Required for the next release

- sign `SHA256SUMS.txt` with cosign keyless OIDC;
- publish the signature bundle next to the checksums;
- verify the signature from the downloaded release, not from the repo;
- fail the tag job if verification fails;
- keep the build-provenance attestation and verify it from the downloaded
  bundle.

Operators can verify the attestation with
`gh attestation verify <asset> --repo <owner>/<repo>`. The release is still
described as **checksummed, not signed** until the cosign requirements above
are met.
