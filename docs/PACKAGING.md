# Endpoint packaging — MSI and deb (test signing)

Status: **test-signed artifacts for 4.3, not a production signature.** The CI
jobs build and verify a Windows MSI and a Linux `.deb`; they do not attach them
to a GitHub Release and they do not make the release “signed”. The release
remains checksummed, not cosign-signed (`docs/RELEASE_SIGNING.md`).

## What is in the packages

| Platform | Artifact | Contents |
|---|---|---|
| Windows | `aegis-agent-<version>-x64.msi` | `aegis-agent.exe`, optional `aegis-etw.exe`, Windows service `AegisAgent`, system environment for unified mode, `C:\ProgramData\Aegis`. |
| Linux | `aegis-agent_<version>_amd64.deb` | `/usr/local/bin/aegis-agent`, optional eBPF collector/object, `aegis-agent.service`, `/etc/aegis-agent/aegis-agent.env.example`, state directory `/var/lib/aegis-agent`. |

Both packages install the agent and **do not contain an enrollment token**. The
token is short-lived and single-use; provision it with MDM/Intune/GPO, an
Ansible/Salt state, or the manual one-liner from Deployment Manager. Starting the
service before the token exists produces a visible failed service, not a fake
successful enrollment.

## Windows MSI

Build locally (Windows, Go, WiX 5, PowerShell 5.1+):

```powershell
dotnet tool install --tool-path .tmp/wix5 wix --version 5.0.2
.\scripts\build-msi.ps1 -Version 4.3.0 -OutDir dist -TestSign
```

`-TestSign` creates an ephemeral self-signed code-signing certificate in
`Cert:\CurrentUser\My`, exports the public certificate next to the MSI and calls
`Set-AuthenticodeSignature` with SHA-256. `Get-AuthenticodeSignature` reports
`UnknownError` on a machine that does not trust the ephemeral root; that is the
expected test-chain result. The build fails if the status is `NotSigned`.
For production, pass `-CertificateThumbprint <thumbprint>` and sign with a
real Authenticode certificate; `signtool.exe` with RFC 3161 timestamping is the
recommended production path. The test certificate is never committed.

Install with MDM or interactively:

```powershell
msiexec /i .\dist\aegis-agent-4.3.0-x64.msi BRAIN_URL=https://aegis.example.com /qn
# Provision the token and ACL, then start the service:
#   C:\ProgramData\Aegis\enroll.token
Start-Service AegisAgent
```

The MSI sets `AEGIS_AGENT_PROFILE=unified`, `AEGIS_AGENT_MODE=full`,
`AEGIS_BRAIN_URL`, `AEGIS_IDENTITY_DIR` and `AEGIS_ENROLL_TOKEN_FILE`. The
token file and `C:\ProgramData\Aegis` ACL are deployment responsibilities; the
MSI does not grant broad write access to ProgramData. Uninstall stops and
removes the service, then removes the installed binaries; the state directory is
retained unless the operator removes it.

## Linux deb

Build locally on Linux (Go, `dpkg-deb`, `gpg`):

```bash
VERSION=4.3.0 ./scripts/build-deb.sh
# or cross-build the binary first and run the packager in a disposable container:
docker run --rm -v "$PWD:/src" -v "$PWD/dist:/out" \
  -e VERSION=4.3.0 -e OUT_DIR=/out \
  -e AGENT_BIN=/src/.tmp/packaging/aegis-agent-linux \
  debian:bookworm-slim \
  bash -lc 'apt-get update -qq && apt-get install -y -qq dpkg-dev gnupg >/dev/null && /src/scripts/build-deb.sh'
```

The default is test signing: an ephemeral RSA key is generated in a temporary
`GNUPGHOME`, the `.deb` gets a detached armored `.asc`, and `gpg --verify` must
pass before the script exits. For production, provide `GPG_KEY_ID` and keep the
private key off the build host where possible. The repository never stores a
private key.

Install:

```bash
sudo dpkg -i aegis-agent_4.3.0_amd64.deb
sudo install -d -m 0750 /etc/aegis-agent
sudo install -m 0600 /dev/null /etc/aegis-agent/enroll.token  # provision via MDM
sudoedit /etc/aegis-agent/aegis-agent.env
sudo systemctl enable --now aegis-agent
```

The package enables but does not start the unit in `postinst`. The unit runs as
root because eBPF/auditd require it; `ProtectHome` and `PrivateTmp` are enabled
and `NoNewPrivileges` is deliberately not forced until the eBPF path has a
capability-based unit. Review that before production.

Verify:

```bash
gpg --verify aegis-agent_4.3.0_amd64.deb.asc aegis-agent_4.3.0_amd64.deb
dpkg-deb --info aegis-agent_4.3.0_amd64.deb
sha256sum -c aegis-agent_4.3.0_amd64.deb.sha256
```

## CI

`.github/workflows/packaging.yml` builds the MSI on `windows-latest` with WiX 5
and test signing, and the `.deb` on `ubuntu-latest` with `dpkg-deb` and an
ephemeral GPG key. It is intentionally a separate workflow so the Kraken branch
can merge without a `ci.yml` conflict. Make this workflow a required branch
check before promotion; its artifacts are named explicitly and are **not**
included in the release bundle. A test-signed package cannot be attached to a
production release.

## Production gaps

- Real Authenticode certificate, timestamping and signer-identity validation.
- Real GPG/cosign release key and documented key custody/rotation.
- Intune/GPO/MDM install, upgrade and uninstall on a clean host.
- RPM/MSIX/opkg/apk packages and Linux repository metadata.
- Package-level SBOM/provenance and a signed package verification path in the
  release smoke test.
- Service-hardening review for Linux capabilities and the Windows ProgramData
  token ACL.

These are tracked in `docs/ROADMAP_LIVE_VALIDATION.md`; a test signature is not a
production signature.
