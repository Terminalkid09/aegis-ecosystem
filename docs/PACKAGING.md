# Endpoint packaging — MSI, deb, RPM and ipk

Status: **production-capable build paths; the CI default is test signing.**
A production artifact requires the operator's Authenticode certificate and
Linux signing key, which are deliberately not stored in this repository.
The tag workflow signs the release checksums with cosign keyless OIDC; the
endpoint packages are signed separately with the platform-native tools.

## What is in the packages

| Platform | Artifact | Contents |
|---|---|---|
| Windows | `aegis-agent-<version>-x64.msi` | `aegis-agent.exe`, optional `aegis-etw.exe`, Windows service `AegisAgent`, system environment for unified mode, `C:\ProgramData\Aegis`. |
| Debian/Ubuntu | `aegis-agent_<version>_amd64.deb` | `/usr/local/bin/aegis-agent`, optional eBPF collector/object, `aegis-agent.service`, `/etc/aegis-agent/aegis-agent.env.example`, state directory `/var/lib/aegis-agent`. |
| RHEL/Rocky/Fedora | `aegis-agent-<version>-1.x86_64.rpm` | Same files as the deb, systemd unit and `%post` enable-without-start. |
| OpenWrt | `aegis-agent_<version>_x86_64.ipk` | `/usr/sbin/aegis-agent`, procd init script and UCI config. The token is not packaged. |

All packages install the agent and **do not contain an enrollment token**. The
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

`-TestSign` creates an ephemeral self-signed certificate in
`Cert:\CurrentUser\My`, exports the public certificate next to the MSI and calls
`Set-AuthenticodeSignature` with SHA-256. `Get-AuthenticodeSignature` reports
`UnknownError` on a machine that does not trust the ephemeral root; that is the
expected test-chain result. The build fails if the status is `NotSigned`.

For production, use any certificate the operator already owns. There is no
Aegis-specific certificate authority and no secret is required in the source
tree:

```powershell
# PFX from a file, password in an environment variable (not on the command line)
$env:AEGIS_MSI_PFX_PASSWORD = Read-Host -AsSecureString | ConvertFrom-SecureString -AsPlainText
.\scripts\build-msi.ps1 -Version 4.3.0 -OutDir dist -ProductionSign `
  -PfxPath C:\keys\aegis-codesign.pfx

# Or a certificate already installed in the Windows certificate store
.\scripts\build-msi.ps1 -Version 4.3.0 -OutDir dist -ProductionSign `
  -CertificateThumbprint <thumbprint>
```

Production signing uses `signtool.exe`, RFC 3161 timestamping (default
`http://timestamp.digicert.com`), `signtool verify /pa`, and requires a
`Valid` Authenticode status with a timestamp. Use `-TimestampUrl` to point at
the operator's timestamp authority and `-SignToolPath` when the SDK is not on
`PATH`. An unencrypted PFX is supported only with `-AllowEmptyPfxPassword`.

The certificate is not bundled by this repository. An internal CA certificate
is production-valid when its root is distributed by GPO/Intune to every target;
a public CA certificate is the alternative for external distribution.

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

Intune/GPO templates and the local post-deployment validator are in
[`deploy/mdm/`](../deploy/mdm/README.md). They are not tenant evidence; the
validator reports `tenant_validation: "not_performed"`.

**MSIX:** not emitted as the service package. MSIX is an application packaging
format and does not register a Windows service like `AegisAgent`; using it here
would produce a package that cannot provide the required background service.
The supported Windows installation contract is the MSI above.

## Linux deb

Build locally on Linux (Go, `dpkg-deb`, `gpg`):

```bash
VERSION=4.3.0 SIGNING_MODE=production GPG_KEY_ID=<fingerprint> \
  ./scripts/build-deb.sh
```

The default `SIGNING_MODE=test` generates an ephemeral RSA key in a temporary
`GNUPGHOME`; that is only for CI and local smoke tests. Production refuses to
build without a key already in `GNUPGHOME`, and `SKIP_SIGN=1` is rejected in
production mode. The `.deb` gets a detached armored `.asc`; `gpg --verify` must
pass before the script exits. `GPG_PASSPHRASE_FILE` or `GPG_PASSPHRASE` can be
used for an unattended passphrase-protected key; the repository never stores a
private key.

The cross-build container recipe remains:

```bash
docker run --rm -v "$PWD:/src" -v "$PWD/dist:/out" \
  -e VERSION=4.3.0 -e OUT_DIR=/out \
  -e AGENT_BIN=/src/.tmp/packaging/aegis-agent-linux \
  debian:bookworm-slim \
  bash -lc 'apt-get update -qq && apt-get install -y -qq dpkg-dev gnupg >/dev/null && /src/scripts/build-deb.sh'
```

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

## RPM

Build on a host with `rpmbuild`:

```bash
VERSION=4.3.0 ./scripts/build-rpm.sh
```

The RPM installs the same binary, systemd unit and environment template, and
uses `%post` only to enable the unit. Sign the RPM with the operator's RPM/GPG
key after the build; the release workflow does not substitute a test key.

## OpenWrt ipk

Build with `binutils` (for `ar`) and Go:

```bash
VERSION=4.3.0 ./scripts/build-opkg.sh
```

The package uses `procd` and `/etc/config/aegis-agent`; it does not embed a
token and does not start until the operator configures `brain_url` and
provisions `/etc/aegis-agent/enroll.token`.

## CI and clean-host validation

`.github/workflows/packaging.yml` builds the MSI, `.deb`, RPM and ipk. It also
runs:

- **MSI install/uninstall** on a fresh `windows-latest` runner: installs the
  MSI, verifies the binary and `AegisAgent` service, uninstalls, and verifies
  both are gone;
- **deb install/uninstall** on a fresh `ubuntu-latest` runner;
- **RPM install/uninstall** in a disposable `rockylinux:9` container;
- **ipk structure** validation (`debian-binary`, `control.tar.gz`,
  `data.tar.gz`).

`workflow_dispatch` with `production_signing=true` runs optional jobs that
consume the operator's repository secrets (`AEGIS_WINDOWS_PFX_BASE64`,
`AEGIS_MSI_PFX_PASSWORD`, `AEGIS_GPG_PRIVATE_KEY`, `AEGIS_GPG_KEY_ID`). These
secrets are only the CI convenience path; the scripts accept the same
certificate/key files directly for self-hosted or offline builds.

## Production boundary

The code paths and clean-host lifecycle tests are part of 4.3. A production
claim still requires the operator's certificate/key and, where applicable, the
actual MDM tenant policy to be applied. Test signing is never represented as a
production signature.
