# Release signing — 4.3.0

Status: 2026-11-21. `SHA256SUMS.txt` is signed by the tag workflow with
**cosign keyless OIDC**; the signature bundle is published next to the release
assets. The endpoint packages are signed separately with Authenticode (MSI) and
the operator's GPG key (deb). A local bundle built outside the tag workflow is
still unsigned until that step runs.

## What is signed

| Artifact | Signature |
|---|---|
| `SHA256SUMS.txt` | `SHA256SUMS.sigstore.json`, cosign keyless OIDC |
| Windows MSI | Authenticode with RFC 3161 timestamp |
| deb | Detached armored GPG `.asc` |
| RPM | Operator RPM/GPG signature (separate signing step) |
| ipk | Package checksum; feed-level signing remains the operator's choice |

The cosign identity is bound to the workflow and tag:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity \
    "https://github.com/<owner>/<repo>/.github/workflows/ci.yml@refs/tags/v4.3.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt
```

The tag job fails if signing or verification fails; it does not publish a
signature it cannot verify. `RELEASE_MANIFEST.json` records that the tag
workflow produces the cosign signature.

## Package signing

The repository never stores private keys or PFX files. The MSI script accepts a
PFX path or a certificate thumbprint and uses `signtool.exe` with RFC 3161
timestamping. The deb script accepts `SIGNING_MODE=production` plus a GPG key
already present in `GNUPGHOME`; test mode uses an ephemeral key and is clearly
labelled as test.

These are deliberate operator-controlled inputs: the product is open source and
must not force a particular certificate authority. A public CA, an internal CA
distributed by GPO/Intune, or an HSM-backed key are all valid as long as the
resulting signature verifies on the target.

## Provenance

The tag workflow also produces a GitHub build-provenance attestation. It binds
the assets to the repository, commit and workflow run; it does not replace the
publisher signature. Verify it with:

```bash
gh attestation verify <asset> --repo <owner>/<repo>
```
