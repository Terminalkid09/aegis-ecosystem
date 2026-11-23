# Aegis server and endpoint packages

The product has three different installation targets. The names reflect the
scope instead of the old `aegis-server` / `aegis-kraken` ambiguity:

| Download | What it installs | Target |
|---|---|---|
| `aegis_<version>_amd64.deb` | **Complete Aegis**: Brain, Link, dashboard/frontend, PostgreSQL, Redis, Caddy and backup, with `aegis.service` | Linux server with Docker |
| `kraken_<version>_amd64.deb` | **Complete Kraken**: app, sensors, broker, RDP endpoint, private PostgreSQL and Redis, with `kraken.service` | Linux server with Docker |
| `aegis-suite_<version>_all.deb` | **Aegis + Kraken together**: metapackage that depends on both complete packages; no duplicated payload | Linux server with Docker |
| `aegis-suite-<version>.tar.gz` | One-file pilot bundle: the three debs, checksums and `install.sh`; includes the agent artifacts for convenience but does not install them | Linux server with Docker |
| `aegis-server-<version>-x64.msi` | **Aegis only on Windows**: Brain, Link, dashboard, PostgreSQL, Redis, Caddy, Compose source, `ak.cmd` and FQDN/ACME/port wizard | Windows server with Docker Desktop |
| `kraken-server-<version>-x64.msi` | **Kraken only on Windows**: app, sensors, broker, RDP, private PostgreSQL/Redis, Compose source and `ak.cmd` | Windows server with Docker Desktop |
| `aegis-suite-<version>-x64.msi` | **Aegis + Kraken together on Windows**: the combined Compose payload, dashboard, `ak.cmd` and wizard | Windows server with Docker Desktop |
| `aegis-agent_<version>_amd64.deb` | **Endpoint only**: `aegis-agent`, optional eBPF helper, `aegis-agent.service` | Debian/Ubuntu endpoint |
| `aegis-agent-<version>-x64.msi` | **Endpoint only**: `aegis-agent.exe`, optional ETW helper, `AegisAgent` service | Windows endpoint |

The Windows server MSIs are not the endpoint agent. They are three alternatives:
`aegis-server` installs Aegis only, `kraken-server` installs Kraken only, and
`aegis-suite` installs both. Each has its own install root, registry settings,
`ak.cmd` in the machine `PATH`, and generated environment; `aegis-suite` is the
package to choose for a combined deployment. They use Docker Desktop and
therefore start at login, not before login; that is the only remaining
boot-parity difference from the Linux packages.

`aegis` is not "backend only": the dashboard/frontend is part of that package.
`kraken` is not "Aegis plus Kraken": it is only the Kraken stack. `aegis-suite`
is the only package that brings both stacks together, and it does that through
two normal packages so their databases, Redis instances, secrets, upgrades and
systemd units remain independent. The metapackage post-install is the
integration point: it attaches Brain/Caddy and the Kraken app to the
`aegis_shared` network, aligns the SSO and signed-ingest secrets, points Kraken
at `aegis-brain:8000`, enables the integration and routes the UI under
`/kraken/`. Installing `aegis` and `kraken` separately does not wire those
secrets; the standalone deployments stay independent.

## Why the agent is still separate

The agent is installed on endpoints, not on the server. It needs a per-endpoint
identity and a short-lived, single-use enrollment token. Installing it from the
server package would put an endpoint service on the server by accident and would
not give the customer a usable endpoint anyway. The Aegis dashboard already
serves the installer and creates the enrollment command; the operator does not
have to find the agent download separately.

The `aegis-suite` **bundle** includes the agent deb/MSI as files so a pilot can
carry one archive to a site. Its `install.sh` installs the three server debs
through the `aegis-suite` metapackage, so the shared network/SSO/ingest wiring
runs; the agent remains an explicit endpoint step and is not installed on the
server. On Windows there is no metapackage: `aegis-suite-<version>-x64.msi` is
the combined payload, while the two single-edition MSIs are for a host that only
needs one stack.

## What the Aegis package contains

`aegis` installs `/opt/aegis/server` with:

- `docker-compose.yml`, the production/mTLS/HA overlays and the Caddyfiles;
- the Brain, Link, frontend and backup sources used by the Compose build;
- `.env.example`;
- `/etc/systemd/system/aegis.service`;
- `/usr/local/lib/aegis/build-server.sh`, `server-env.sh` and the maintainer
  scripts.

## What the Kraken package contains

`kraken` installs `/opt/aegis/kraken` with:

- a standalone `docker-compose.yml` for the Kraken app, sensors, broker, RDP
  endpoint, private database and private Redis;
- the `services/kraken` build context;
- `/etc/systemd/system/kraken.service`;
- `/usr/local/lib/aegis/build-kraken.sh`, `kraken-up.sh`, `kraken-down.sh` and
  `kraken-env.sh`.

Neither server package embeds prebuilt OCI images. The first `systemctl start`
builds them from the packaged source, then starts the stack. That needs network
access to the Python/Node/Maven image registries and takes several minutes. A
marker in `/var/lib/aegis/<component>/images.ok` makes later boots fast; an
upgrade removes it so the changed service is rebuilt.

## Privileges and first start

The server packages install as `root`, generate root-owned secrets with mode
`0600`, install units as `0644`, and install the helper scripts as `0755`. The
units run as `root` on purpose: they need the Docker socket and host-level
bring-up. They do **not** run as the logged-in desktop user.

The unit uses `Wants=docker.service`, not `Requires=docker.service`. On a real
Linux server Docker Engine is ordered before Aegis. On Docker Desktop WSL the
socket can exist without a systemd `docker.service`; the unit can still start if
the Docker CLI, Compose v2 and daemon are reachable. If they are not, the build
and Compose command fail visibly instead of pretending the stack is healthy.

Prerequisites on the server:

```bash
sudo systemctl enable --now docker
docker compose version
docker info
```

Install one stack:

```bash
sudo apt install ./aegis_4.3.0_amd64.deb
sudo apt install ./kraken_4.3.0_amd64.deb
```

Install both through the small metapackage (keep the three debs in one directory):

```bash
sudo apt install ./aegis-suite_4.3.0_all.deb \
  ./aegis_4.3.0_amd64.deb ./kraken_4.3.0_amd64.deb
```

Or use the one-file bundle:

```bash
tar -xzf aegis-suite-4.3.0.tar.gz
sudo ./aegis-suite-4.3.0/install.sh
# The installer prints ak url after the metapackage is configured.
```

The post-install script:

1. creates `/opt/aegis/server` or `/opt/aegis/kraken`;
2. generates `/etc/aegis/server.env` or `/etc/aegis/kraken.env` with random
   secrets and mode `0600` if it does not already exist;
3. creates the `secrets/` directory with mode `0750`;
4. enables the unit and verifies `systemctl is-enabled`;
5. starts the unit with `systemctl start --no-block` only after `docker compose
   version` and `docker info` succeed.

Check the result:

```bash
systemctl is-enabled aegis kraken
systemctl status aegis --no-pager
journalctl -u aegis -f
docker compose --env-file /etc/aegis/server.env -f /opt/aegis/server/docker-compose.yml ps
```

Aegis listens on `https://aegis.local` (Caddy internal CA by default) and on
`http://localhost:3000` for the dashboard. The local port is configurable with
`AEGIS_UI_PORT`; if it is occupied, the package selects the first free port in
`3000-3099` and records it in `/etc/aegis/server.env`. Kraken listens on
`http://127.0.0.1:8001` by default and keeps sensors internal. Change
`AEGIS_DOMAIN`/`ACME_EMAIL` and the Kraken honeypot bind only as documented in
`docs/OPERATIONS.md` and `services/kraken/README.md`.

## Operator CLI: `ak`

Both server packages install the same operator CLI and expose it as
`/usr/local/bin/ak`. The two packages keep separate copies under
`/usr/local/lib/aegis/ak-aegis` and `ak-kraken`; `update-alternatives` selects
one, so installing both never overwrites a package file. The command is
headless by design: the dashboard is web, not a desktop icon. The complete
reference is installed as `/usr/share/doc/aegis/AK_CLI.md` and is also in the
repository at `docs/AK_CLI.md`.

```bash
ak --help
ak help logs
ak status
sudo ak start                 # start every installed stack
sudo ak start kraken          # or select one component
ak ps
ak logs aegis -f
ak doctor
ak url kraken
sudo ak configure --domain soc.example.com --email ops@example.com
sudo ak configure --port 3005
```

The CLI uses `systemctl` for the lifecycle and Docker Compose for container
status/logs. `start`/`stop`/`restart`/`configure` require root; `status`,
`url`, `doctor` and normally `ps`/`logs` do not. The first `start` builds the
images and can take several minutes; use `ak status` and `ak ps` to follow the
result, and `ak doctor` to check systemd, Docker, env permissions and boot
enablement. `ak doctor` exits non-zero when a required check fails.

### Updates and release selection

`ak update` is the supported upgrade path. It installs the release package,
which updates both the CLI and the service payload, and restarts the units by
default. The package checksum is mandatory; a missing or mismatched SHA-256 is a
hard failure. `ak update --check` is read-only, and `--version X.Y.Z` pins a
release instead of taking the latest stable one. A downgrade requires
`--allow-downgrade` and a verified database backup, because migrations are not
reversed automatically. See [the release policy](../docs/RELEASE_POLICY.md) for
which lines are maintained and which are EOL.

### Dashboard URL and port

The `aegis` package asks for the public hostname, ACME email and local dashboard
port through debconf. Noninteractive installs can preseed them or set
`AEGIS_DOMAIN`, `ACME_EMAIL`, `AEGIS_UI_PORT` and optionally
`AEGIS_PUBLIC_URL` in the environment. The generated values live in
`/etc/aegis/server.env` and can be changed later with `ak configure`.

The local dashboard binds to `127.0.0.1:${AEGIS_UI_PORT:-3000}`; Caddy keeps
using the internal frontend port 3000. If the requested host port is occupied,
the package tries the first free port in `3000-3099` and records it. A public
FQDN uses Caddy ACME and must have DNS on this host plus inbound 80/443.

## Self-signed pilot signing

The default server build uses a persistent self-signed GPG key:

```bash
VERSION=4.3.0 SIGNING_MODE=self-signed ./scripts/build-server-deb.sh
```

It writes `aegis-pilot-signing-key.asc` next to the packages. The private key
stays in `$HOME/.local/share/aegis-gpg` (or your existing `GNUPGHOME`), not in
the package. Verify with:

```bash
gpg --import aegis-pilot-signing-key.asc
gpg --verify aegis_4.3.0_amd64.deb.asc aegis_4.3.0_amd64.deb
gpg --verify kraken_4.3.0_amd64.deb.asc kraken_4.3.0_amd64.deb
```

This is a **self-signed pilot identity**, not a publicly trusted publisher. A
customer who has not imported the public key will see an untrusted signature;
that is the expected trade-off. The MSI uses the same self-signed model when
built with `-TestSign`: Windows reports `UnknownError`/unknown publisher until
the certificate is trusted on the target. A production release still requires
the operator's paid/company Authenticode certificate and a protected GPG key;
`SIGNING_MODE=production` fails closed without them.

## Upgrade and removal

A package upgrade rebuilds changed images on the next start because the
post-install script removes the `images.ok` marker:

```bash
sudo apt install ./aegis_4.3.0_amd64.deb
sudo systemctl restart aegis
```

`apt remove` stops and disables the unit. It does **not** delete
`/etc/aegis/*.env` or the Docker volumes: database, PKI, artifacts and Kraken
samples remain. Back up those secrets and volumes before a `purge`.

## Boundaries

- A real host reboot is the only proof that the enabled unit and Docker come
  back together. The package configures systemd, enablement, secrets and the
  start path; a host with Docker Engine must still be rebooted.
- The Windows server MSIs install the selected Compose stack, the dashboard and
  the global `ak` command. They do **not** install a pre-login Windows service:
  Docker Desktop is per-user, so the supported bring-up is `ak start` after
  login or a scheduled task at logon. A true pre-login server requires a
  per-machine container runtime or a native Windows port. The endpoint MSI is a
  separate product and does not install the server.
- The Docker Desktop runtime was verified healthy on 2026-11-22 (Brain, Link,
  frontend, Caddy, Kraken, sensors and broker; HTTP 200 from the main
  endpoints). The Windows package reuses that runtime and source; the remaining
  difference is boot timing, not missing components.
- The soak runner is a deferred internal test harness. It is not in any package,
  not a customer step and not a 4.3 release gate.
