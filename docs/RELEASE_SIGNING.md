# Release signing — 4.3.0

Status: 2026-11-22. `SHA256SUMS.txt` is signed by the tag workflow with
**cosign keyless OIDC**; the signature bundle is published next to the release
assets. The endpoint packages are signed separately with Authenticode (MSI) and
GPG (deb). For the 4.3 controlled pilot, the accepted package identity is
**self-signed**, not a publicly trusted publisher; the production certificate
and key remain operator inputs. A local bundle built outside the tag workflow is
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

## Cost and free options

Authenticode is the only paid part of the chain:

- a publicly trusted code-signing certificate is **not free**. OV/EV code
  signing requires identity validation and a paid CA subscription (typically
  hundreds of euros/dollars per year; Azure Trusted Signing is a metered,
  usually cheaper option for a small team). A self-signed certificate is free,
  but Windows on the customer machine does not trust it: that is test signing,
  not a release signature;
- this repository cannot buy or issue a publicly trusted certificate. The
  operator must supply the PFX/HSM identity; the build and verification path is
  already implemented and fails closed without it;
- GPG is free: generating an OpenPGP key costs nothing and has no CA. The real
  cost is key custody, publication and rotation. A production key should be
  offline/HSM-backed and published with its fingerprint; `gpg --quick-gen-key`
  is for a test key, not a release key;
- cosign keyless signing is free through GitHub OIDC. It proves the workflow
  and repository identity for the tag, not a verified company identity.

So: a production MSI needs a purchased/company-issued Authenticode identity; a
production deb needs a GPG key you can generate for free, but must protect and
distribute. Neither can be invented locally, and a test-signed file is never
relabelled as production.

## Self-signed pilot profile (accepted for the 4.3 pilot)

The 4.3 server packages default to a persistent self-signed GPG key:

```bash
VERSION=4.3.0 SIGNING_MODE=self-signed ./scripts/build-server-deb.sh
gpg --import dist/aegis-pilot-signing-key.asc
gpg --verify dist/aegis_4.3.0_amd64.deb.asc dist/aegis_4.3.0_amd64.deb
```

The private key stays in the local `GNUPGHOME` (default
`$HOME/.local/share/aegis-gpg`, or the operator's existing `GNUPGHOME`) and is
not packaged. A target that has not imported the public key sees an untrusted
signature; that is expected. The MSI uses the existing `-TestSign` self-signed
path and reports `UnknownError`/unknown publisher until the certificate is
trusted. This is a pilot trade-off, not a trusted-publisher claim.

`scripts/release-smoke.py` still requires `production` by default. The explicit
pilot override is:

```bash
python scripts/release-smoke.py release --allow-self-signed
```

It accepts only a sidecar labelled `self-signed`; it never relabels one as
`production`. A production GA release must use the operator's Authenticode
certificate and protected GPG key.

## Test-signed is not a production release artifact

`-TestSign` and the default `build-deb.sh` test mode exist for CI and local
smoke tests. They use an ephemeral/self-signed identity; the server build's
`self-signed` mode is the explicitly accepted pilot profile above, while the
ephemeral `test` mode remains CI-only. Neither is a production signature. Every
package build writes a
`<package>.signing.json` sidecar with `mode` set to `test`, `production` or
`unsigned`. A release is accepted only when the sidecar says `production`, the
Authenticode status is `Valid`, the signer is the operator certificate and an
RFC 3161 timestamp is present (for the MSI); the deb has a detached GPG
signature made with the production key.

If the production PFX/GPG key is missing, the packaging job fails closed. Do not
relabel a test-signed file or attach it to a release. `scripts/release-smoke.py`
rejects a release directory containing a `test`/`unsigned` sidecar, an MSI
whose status is not `Valid`, or a production MSI without a timestamp.

## Provenance

The tag workflow also produces a GitHub build-provenance attestation. It binds
the assets to the repository, commit and workflow run; it does not replace the
publisher signature. Verify it with:

```bash
gh attestation verify <asset> --repo <owner>/<repo>
```
