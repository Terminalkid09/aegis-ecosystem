# Release signing decision — 4.2

Status: 2026-11-17.

## Decision

`v4.2.0` remains **checksummed, not cosign-signed**. This is an explicit
limitation, not a claim that the release is signed. `SHA256SUMS.txt` and
`RELEASE_MANIFEST.json` protect against corruption in transit and let a
downloader verify the exact bytes; they do not authenticate the publisher.

## Why

Keyless cosign needs a working OIDC identity, a pinned installer and a
verification path in the release smoke test. Adding only the signing step
would produce a signature that nobody verifies, which is worse than an
honest unsigned release. The Windows NodeTrace artifact, per-image SBOMs
and the release smoke test are the 4.2 release-integrity priorities.

## Required for the next release

- sign `SHA256SUMS.txt` with cosign keyless OIDC;
- publish the signature bundle next to the checksums;
- verify the signature from the downloaded release, not from the repo;
- fail the tag job if verification fails.

## Build provenance

The tag workflow produces a GitHub build-provenance attestation for every file
in `release/` with `actions/attest-build-provenance`. It binds the assets to the
repository, the commit and the workflow run; it does **not** prove the identity
of a human publisher and it is not a cosign signature. Operators can verify it
with `gh attestation verify <asset> --repo <owner>/<repo>`.

The source archive and the images are built from the tagged checkout in the
same workflow. That is provenance by construction; the attestation makes it
verifiable, but the release is still **checksummed, not signed**. The next
release must add cosign keyless signing and verify both the signature and the
attestation from the downloaded bundle.
