# Packaging — endpoints and servers

Status: **self-signed pilot packages; production signing remains an operator
input.** The default server build uses a persistent self-signed GPG key, and
the MSI uses the existing `-TestSign` self-signed path. A trusted production
artifact still requires the operator's Authenticode certificate and protected
GPG key; self-signed is never relabelled as production. The tag workflow signs
the release checksums with cosign keyless OIDC; the endpoint packages are
signed separately with the platform-native tools.

The endpoint MSI and the agent deb install **only the endpoint**. The Windows
server MSI and the Linux server packages install the dashboard, Brain, Link,
PostgreSQL, Redis, Caddy and Kraken. A customer never installs the soak runner:
it is a deferred internal test harness, not a product component.

## What is in the packages

| Platform | Artifact | Contents |
|---|---|---|
| Windows endpoint | `aegis-agent-<version>-x64.msi` | `aegis-agent.exe`, optional `aegis-etw.exe`, Windows service `AegisAgent`, system environment for unified mode, `C:\ProgramData\Aegis`. |
| Windows server | `aegis-server-<version>-x64.msi` | Aegis-only Compose payload, dashboard, `ak.cmd` on the machine `PATH`, wizard for FQDN/ACME email/port; uses Docker Desktop. |
| Windows server | `kraken-server-<version>-x64.msi` | Kraken-only Compose payload, private database/Redis, `ak.cmd` on the machine `PATH`; uses Docker Desktop. |
| Windows server | `aegis-suite-<version>-x64.msi` | Combined Aegis + Kraken Compose payload, dashboard, `ak.cmd` and wizard; uses Docker Desktop. |
| Debian/Ubuntu | `aegis-agent_<version>_amd64.deb` | `/usr/local/bin/aegis-agent`, optional eBPF collector/object, `aegis-agent.service`, `/etc/aegis-agent/aegis-agent.env.example`, state directory `/var/lib/aegis-agent`. |
| RHEL/Rocky/Fedora | `aegis-agent-<version>-1.x86_64.rpm` | Same files as the deb, systemd unit and `%post` enable-without-start. |
| OpenWrt | `aegis-agent_<version>_x86_64.ipk` | `/usr/sbin/aegis-agent`, procd init script and UCI config. The token is not packaged. |
| Debian/Ubuntu server | `aegis_<version>_amd64.deb` | **Complete Aegis**: Brain, Link, dashboard/frontend, PostgreSQL, Redis, Caddy and backup; Compose files; `aegis.service`; generated `/etc/aegis/server.env`. |
| Debian/Ubuntu server | `kraken_<version>_amd64.deb` | **Complete Kraken**: app, sensors, broker, RDP endpoint, private PostgreSQL and Redis; Compose file; `kraken.service`; generated `/etc/aegis/kraken.env`. |
| Debian/Ubuntu server | `aegis-suite_<version>_all.deb` | Combined Aegis + Kraken download: metapackage that installs both complete stacks through `Depends: aegis, kraken` and wires their shared network/SSO/ingest; no duplicated payload. |
| Debian/Ubuntu server | `aegis-suite-<version>.tar.gz` | One-file pilot bundle: the three debs, agent artifacts for convenience, checksums and `install.sh`; the installer does **not** install the agent. |

All endpoint packages install the agent and **do not contain an enrollment token**. The
token is short-lived and single-use; provision it with MDM/Intune/GPO, an
Ansible/Salt state, or the manual one-liner from Deployment Manager. Starting the
service before the token exists produces a visible failed service, not a fake
successful enrollment. The server packages are separate and are described in
"Server packages" below; they do not contain the endpoint agent. `aegis` is
the whole Aegis platform including the dashboard, not a backend-only package;
`kraken` is only Kraken, not Aegis plus Kraken. `aegis-suite` is the combined
Aegis + Kraken download; it brings both stacks together while keeping their
lifecycles separate. Its
post-install is the integration point: a shared `aegis_shared` network, matching
SSO/ingest secrets, Kraken pointed at `aegis-brain:8000`, and the UI under
`/kraken/`. Standalone `aegis` or `kraken` installs are deliberately not wired
to each other.

## Windows packages

### Endpoint agent MSI

Build locally (Windows, Go, WiX 5, PowerShell 5.1+):

```powershell
dotnet tool install --tool-path .tmp/wix5 wix --version 5.0.2
.\.tmp\wix5\wix.exe extension add -g WixToolset.Util.wixext/5.0.2
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

`BRAIN_URL` accepts the server origin (`https://aegis.example.com`) or the API
base (`https://aegis.example.com/api/v1`); the agent appends `/api/v1` when the
URL carries no path, so both the MSI property and the Deployment Manager
one-liner resolve to the same endpoints. In service mode the agent mirrors its
log to `C:\ProgramData\Aegis\agent.log`, including startup failures that would
otherwise reach the Event Log only as `terminated with error 1`.

The MSI sets `AEGIS_AGENT_PROFILE=unified`, `AEGIS_AGENT_MODE=full`,
`AEGIS_BRAIN_URL`, `AEGIS_IDENTITY_DIR` and `AEGIS_ENROLL_TOKEN_FILE`. It also
configures Windows service recovery (three restarts, 5 seconds apart, reset
after one day) through the WiX Util extension. The token file and
`C:\ProgramData\Aegis` ACL are deployment responsibilities; the
MSI does not grant broad write access to ProgramData. Uninstall stops and
removes the service, then removes the installed binaries; the state directory is
retained unless the operator removes it.

Intune/GPO templates and the local post-deployment validator are in
[`deploy/mdm/`](../deploy/mdm/README.md). They are not tenant evidence; the
validator reports `tenant_validation: "not_performed"`.

### Server MSI

Build the Windows server package on Windows with WiX 5 and PowerShell 5.1+:

```powershell
.\scripts\build-server-msi.ps1 -Version 4.3.0 -OutDir dist -TestSign
```

The Windows matrix mirrors the Linux packages:

```powershell
.\scripts\build-server-msi.ps1 -Edition aegis  -Version 4.3.0 -TestSign
.\scripts\build-server-msi.ps1 -Edition kraken -Version 4.3.0 -TestSign
.\scripts\build-server-msi.ps1 -Edition suite  -Version 4.3.0 -TestSign
```

It produces `aegis-server-4.3.0-x64.msi`, `kraken-server-4.3.0-x64.msi` and
`aegis-suite-4.3.0-x64.msi`. Each MSI is self-contained and installs:

- the selected Compose project under `C:\Program Files\Aegis Server`,
  `C:\Program Files\Kraken Server` or `C:\Program Files\Aegis Suite`;
- a `bin` directory with `ak.cmd`, `ak.ps1` and `configure-server.ps1`;
- `server.env` or `kraken.env` on the first `ak start`, with random secrets and
  an Administrators/SYSTEM-only ACL;
- the machine `PATH` entry for `...\bin`;
- Aegis/suite also install the FQDN/ACME/port wizard; Kraken-only skips it
  because it has no public TLS edge.

Silent installs use the same properties:

```powershell
msiexec /i .\aegis-server-4.3.0-x64.msi /qn `
  AEGIS_DOMAIN=soc.example.com ACME_EMAIL=ops@example.com AEGIS_UI_PORT=3005
msiexec /i .\aegis-suite-4.3.0-x64.msi /qn `
  AEGIS_DOMAIN=soc.example.com ACME_EMAIL=ops@example.com AEGIS_UI_PORT=3005
```

After installation, run `ak configure` (read-only) or `ak configure --domain ...`
from an elevated PowerShell; the first `ak start` generates the env file, builds
the images and starts Compose. `ak doctor` fails closed if Docker Desktop,
Compose v2 or the daemon is missing. `ak update --check` resolves the latest
published release; `ak update --version X.Y.Z` pins one and verifies the
SHA-256 sidecar before running `msiexec`. The server MSIs do **not** create a
pre-login service; Docker Desktop is per-user. This is the remaining difference
from the Linux packages, which own a systemd unit.

Every server MSI is validated with `wix msi validate`. ICE61 (`WIX1076`) is
suppressed **by name** (`wix msi validate -sice ICE61 <msi>`) because
`MajorUpgrade` sets `AllowDowngrades="yes"` on purpose and declares no `Maximum`
version. The warning is expected, the downgrade is intentional, and every other
ICE stays enabled; CI runs the same command for the three editions.

**MSIX:** not emitted as the service package.**MSIX:** not emitted as the service package. MSIX is an application packaging
format and does not register a Windows service like `AegisAgent`; using it here
would produce a package that cannot provide the required background service.
The supported Windows installation contracts are the endpoint MSI and the server
MSI above.

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

## Server packages — Aegis, Kraken and suite

Aegis and Kraken are two separate microservices with separate databases, Redis
instances, secrets and lifecycles. The package names now describe the complete
product, not an internal component:

- `aegis` installs `/opt/aegis/server` with `docker-compose.yml`, the
  production/mTLS/HA overlays, the Caddyfiles, the Brain/Link/frontend/backup
  source build contexts and `/etc/systemd/system/aegis.service`;
- `kraken` installs `/opt/aegis/kraken` with a standalone Compose file,
  the `services/kraken` build context and `/etc/systemd/system/kraken.service`;
- `aegis-suite` is a metapackage with `Depends: aegis (= version), kraken (=
  version)`; it has no service and no duplicated payload. The bundle is the
  one-file download for a pilot that cannot use a repository;
- both generate `/etc/aegis/server.env` or `/etc/aegis/kraken.env` with random
  secrets, mode `0600`, and never overwrite an existing file;
- both enable the unit and verify `systemctl is-enabled`; the post-install
  starts with `systemctl start --no-block` only after `docker compose version`
  and `docker info` succeed.

They do **not** embed prebuilt OCI images. The first start runs
`docker compose build` from the packaged source, then
`docker compose up -d --remove-orphans`. That first start needs network access to
base-image registries and takes several minutes; later boots use
`/var/lib/aegis/<component>/images.ok`, and a package upgrade removes the marker
so the changed service is rebuilt. An offline install must build and
`docker save` the images separately; 4.3 does not automate that.

Build all three packages and the bundle on Linux or in a Debian container:

```bash
VERSION=4.3.0 ./scripts/build-server-deb.sh
```

Install one stack, both stacks, or the suite on a host with Docker Engine and Compose v2 enabled at boot:

```bash
sudo apt install ./aegis_4.3.0_amd64.deb
sudo apt install ./kraken_4.3.0_amd64.deb
# or both through the metapackage, keeping the three debs together:
sudo apt install ./aegis-suite_4.3.0_all.deb \
  ./aegis_4.3.0_amd64.deb ./kraken_4.3.0_amd64.deb
systemctl is-enabled aegis kraken
systemctl status aegis --no-pager
journalctl -u aegis -f
ak status
ak url
```

### Dashboard port, public URL and TLS

The `aegis` package asks for the public hostname, ACME email and local dashboard
port through debconf. Noninteractive installs can preseed the same values or set
`AEGIS_DOMAIN`, `ACME_EMAIL`, `AEGIS_UI_PORT` and optionally
`AEGIS_PUBLIC_URL` in the environment. The values are written once to
`/etc/aegis/server.env`; `ak configure` changes them later without touching
generated secrets.

The dashboard binds to `127.0.0.1:${AEGIS_UI_PORT:-3000}`. Caddy continues to
proxy to the frontend's internal port 3000. If the requested host port is busy,
the package selects the first free port in `3000-3099` and records it, so a
workstation with another service on 3000 still gets a working local URL. A
public URL requires DNS pointing at the host, inbound 80/443 for ACME, a real
`ACME_EMAIL`, and matching `AEGIS_DOMAIN`, `PUBLIC_BASE_URL` and
`ALLOWED_ORIGINS`.

```bash
sudo ak configure --domain soc.example.com --email ops@example.com
sudo ak configure --port 3005
sudo ak restart aegis
ak url
```

See [the complete `ak` reference](AK_CLI.md).

The units are `Type=oneshot` with `RemainAfterExit=yes`: they are the boot-time
bring-up, while the containers carry `restart: unless-stopped`. `Restart` is
empty for the unit by design; `systemctl is-enabled` is the reboot contract.

Each server package also installs an operator CLI exposed as `/usr/local/bin/ak`.
`aegis` and `kraken` ship separate copies and `update-alternatives` selects one,
so the packages do not conflict. Typical use:

```bash
ak --help
ak status
sudo ak start [aegis|kraken]
ak ps
ak logs aegis -f
ak doctor
```

`start`, `stop`, `restart` and `configure` require root and call systemd;
`status`, `ps`, `logs`, `url` and `doctor` show the real unit/container state.
There is no desktop icon: this is a headless web service, and the dashboard is
opened in a browser. The complete command reference is [AK_CLI.md](AK_CLI.md).
Both units run as `root` on purpose: they need the Docker socket and host-level
bring-up. Secrets are root-owned `0600`; helpers are `0755`; units are `0644`.
The units use `Wants=docker.service`, not `Requires`, so Docker Desktop WSL can
start them when the CLI/socket is available; a normal Linux server still orders
Docker Engine first. Removal stops and disables the unit but keeps
`/etc/aegis/*.env` and the Docker volumes; back them up before a purge.

The Windows server path is Docker Desktop, delivered by the three server MSIs.
On 2026-11-22 the same Compose stack was verified healthy on Docker Desktop:
Brain, Link, frontend, Caddy, Kraken, sensors and broker were healthy, with HTTP
200 from Brain/frontend/Kraken and Caddy. The backend is cross-platform and the
server MSIs package the same source. Docker Desktop is a per-user desktop
application, so the MSIs cannot honestly provide pre-login server availability:
use `ak start` after login or a scheduled task at logon. A true pre-login
service requires a per-machine container runtime or a native Windows port. This
is a boot-timing limitation, not a missing component. The endpoint MSI still
accepts `BRAIN_URL` for a custom server origin; that property configures the
agent, not the dashboard. The
server packages are self-signed with the pilot GPG key by default; they are not
publicly trusted. The endpoint MSI/deb use the same self-signed/pilot model
until the operator supplies a trusted Authenticode/GPG identity.

- The WSL test installed and enabled the packages, checked `0600`/`0644`/`0755`
  permissions and parsed the units with a temporary `docker.service` stub. The
  Windows Docker CLI is visible inside this WSL distro, but Compose v2 and the
  daemon socket are not integrated, so `ak start` fails closed before starting
  the unit. A real Linux host with Docker Engine must still run the first
  `systemctl start`, check the containers and reboot.

### Self-signed pilot signing

```bash
VERSION=4.3.0 SIGNING_MODE=self-signed ./scripts/build-server-deb.sh
gpg --import dist/aegis-pilot-signing-key.asc
gpg --verify dist/aegis_4.3.0_amd64.deb.asc dist/aegis_4.3.0_amd64.deb
```

The public key is in `dist/aegis-pilot-signing-key.asc`; the private key stays
in the local `GNUPGHOME` (default `$HOME/.local/share/aegis-gpg`, or the
operator's existing `GNUPGHOME`) and is never packaged.
A customer who has not imported the key sees an untrusted signature. That is
the accepted pilot trade-off, not a trusted publisher claim. GPG is optional for
a local pilot: SHA-256 is the integrity check, while a self-signed signature adds
provenance only if the public key is distributed. `SIGNING_MODE=unsigned` is
available when an untrusted-signature warning would confuse a demo; the default
pilot profile remains self-signed. `SIGNING_MODE=production` requires
`GPG_KEY_ID` and a protected key, and fails closed without it.
`scripts/release-smoke.py --allow-self-signed` is the explicit pilot override;
the default release check still requires `production`.

## CI and clean-host validation

`.github/workflows/packaging.yml` builds the MSI, endpoint `.deb`, RPM, ipk and
the complete `aegis`/`kraken`/`aegis-suite` server packages. It also
runs:

- **MSI install/uninstall** on a fresh `windows-latest` runner: installs the
  MSI, verifies the binary and `AegisAgent` service, uninstalls, and verifies
  both are gone;
- **deb install/uninstall** on a fresh `ubuntu-latest` runner;
- **RPM install/uninstall** in a disposable `rockylinux:9` container;
- **ipk structure** validation (`debian-binary`, `control.tar.gz`,
  `data.tar.gz`);
- **server packages** build, metadata/signature/checksum verification, dashboard
  and Kraken payload checks, and bundle inspection on a clean `ubuntu-latest`
  runner. Actual Docker start/reboot remains a host test.
- **Windows server MSIs** build and administrative extraction on a clean
  `windows-latest` runner for all three editions: checks `ak.cmd`,
  `configure-server.ps1`, the Aegis/Kraken/suite payloads and the wizard. Docker
  Desktop start remains a host test.

- **tag releases** (`v*`): job `release_assets` waits for the release created by
  `ci.yml`, checks that the tag matches the built version and attaches the
  packaged artifacts with their `.sha256` sidecars, never overwriting an asset
  that already exists. Test-signed server MSIs (the CI default) are skipped with
  a warning: a public release requires the production signing path, so until the
  server MSI is built with the operator certificate, no MSI is attached and
  `ak update` on Windows fails closed with a 404 rather than installing a test
  certificate. `ci.yml` remains the only job that creates the release.

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
