# `ak` operator CLI

Status: **4.3.0 pilot**. `ak` is the supported command-line interface for the
packaged Aegis and Kraken **server** stacks. It is not a desktop launcher. The
Windows endpoint MSI does not install it; the separate Windows server MSI does,
as `C:\Program Files\Aegis Server\bin\ak.cmd` on the machine `PATH`.

## What installs it

| Artifact | Installs `ak`? | Components it can manage |
|---|---|---|
| `aegis_<version>_amd64.deb` | Yes | Aegis only |
| `kraken_<version>_amd64.deb` | Yes | Kraken only |
| `aegis-suite_<version>_all.deb` | Yes, through its two dependencies | Aegis and Kraken |
| `aegis-suite-<version>.tar.gz` | Yes, when its server debs are installed | Aegis and Kraken |
| `aegis-server-<version>-x64.msi` | Yes, on Windows | Aegis only through Docker Desktop |
| `kraken-server-<version>-x64.msi` | Yes, on Windows | Kraken only through Docker Desktop |
| `aegis-suite-<version>-x64.msi` | Yes, on Windows | Aegis and Kraken together through Docker Desktop |
| `aegis-agent-<version>-x64.msi` | No | None: this is the endpoint agent |

The server packages install a private copy under
`/usr/local/lib/aegis/ak-aegis` or `ak-kraken`. `update-alternatives` exposes
one of them as `/usr/local/bin/ak`, so installing both never overwrites a
package-owned file. If only Kraken is installed, `ak` manages only Kraken.

The combined download is `aegis-suite_<version>_all.deb`; it is a metapackage,
not a third copy of the payload. It depends on both complete packages and wires
their shared network, SSO and ingest settings. The `.tar.gz` is the single-file
offline bundle around the same debs.

## Install and first configuration

Install Docker Engine with the Compose v2 plugin first:

```bash
sudo systemctl enable --now docker
docker compose version
docker info
```

Install one stack, or both through the suite:

```bash
sudo apt install ./aegis_4.3.0_amd64.deb
sudo apt install ./kraken_4.3.0_amd64.deb

# Both stacks, keeping the three files in one directory:
sudo apt install ./aegis-suite_4.3.0_all.deb \
  ./aegis_4.3.0_amd64.deb ./kraken_4.3.0_amd64.deb
```

The `aegis` package asks for the public hostname, ACME email and local dashboard
port through debconf. For an unattended install, preseed it:

```bash
sudo debconf-set-selections <<'EOF'
aegis aegis/domain string soc.example.com
aegis aegis/acme_email string ops@example.com
aegis aegis/ui_port string 3000
EOF
sudo DEBIAN_FRONTEND=noninteractive apt install ./aegis_4.3.0_amd64.deb
```

Environment variables are also accepted for immutable images and automation.
They take precedence over the debconf values:

```bash
sudo AEGIS_DOMAIN=soc.example.com \
  ACME_EMAIL=ops@example.com \
  AEGIS_UI_PORT=3005 \
  DEBIAN_FRONTEND=noninteractive \
  apt install ./aegis_4.3.0_amd64.deb
```

`AEGIS_PUBLIC_URL` can override the public origin when the browser-facing URL
is not simply `https://<domain>`.

After installation, verify and configure:

```bash
ak status
ak doctor
ak url
sudo ak configure --domain soc.example.com --email ops@example.com
sudo ak restart aegis
```

`ak configure` changes `/etc/aegis/server.env` without touching generated
secrets. It preserves unrelated `ALLOWED_ORIGINS` entries and adds the HTTPS
origin, the local dashboard origin and `http://localhost:5173` (the Vite
development origin).

## Port 3000 fallback

The dashboard is bound to `127.0.0.1:${AEGIS_UI_PORT:-3000}`; Caddy still reaches
the frontend internally on port 3000. This separation matters: the container
port is fixed, while the host port is configurable.

At install time the package:

1. tries the requested port, default `3000`;
2. if it is already listening, scans `3000-3099` and selects the first free
   port;
3. writes the selected value to `/etc/aegis/server.env` as `AEGIS_UI_PORT`;
4. prints the fallback on stderr and keeps `ALLOWED_ORIGINS` in sync.

When `ak start` finds a stopped Aegis unit whose recorded port is occupied, it
selects a free port and records it before invoking systemd. The unit's build
helper performs the same check at boot, but leaves the port alone when the
running container is the existing Aegis frontend. This is a deliberate
fail-safe for workstations where another development server owns port 3000. If
you request a specific port with `ak configure --port`, an occupied port is a
hard error rather than a silent change:

```bash
sudo ak configure --port 3005
sudo ak restart aegis
ak url
```

Example output:

```text
Aegis dashboard: https://soc.example.com/  (local: http://localhost:3005)
```

## Public URL and TLS

Three values must agree:

| Setting | Meaning |
|---|---|
| `AEGIS_DOMAIN` | Hostname Caddy serves and requests a certificate for |
| `ACME_EMAIL` | ACME account email; `internal` keeps Caddy's internal CA |
| `PUBLIC_BASE_URL` | Public origin used by OIDC callbacks and deployment links |

For a real FQDN:

- point DNS A/AAAA at the host;
- allow inbound ports 80 and 443 for the ACME challenge and HTTPS;
- set a real ACME email;
- keep `PUBLIC_BASE_URL` on the same origin;
- do not expose the lab stack directly to the Internet without the documented
  TLS and firewall controls.

The package does not issue a publicly trusted certificate for `aegis.local`;
that name is lab-only and uses Caddy's internal CA.

## Commands

| Command | Root? | Behavior |
|---|---|---|
| `ak --help` | No | Full command reference. |
| `ak help <command>` | No | Detailed help for one command. |
| `ak version` | No | CLI and installed package versions. |
| `ak status [component]` | No | systemd active/enabled state. |
| `ak ps [component]` | No* | Compose containers, health and ports. |
| `ak logs [component] [-f] [--tail N]` | No* | Container logs; default tail 100. |
| `ak doctor` | No* | Read-only checks for prerequisites, files and memory budget. || `ak doctor` | No* | Read-only prerequisite and file checks. |
| `ak url [component]` | No | Public and local URLs from the env files. |
| `ak configure [options]` | Yes | Change hostname, email, public URL or local port. |
| `ak update [options]` | Yes* | Install a selected release, update the CLI and restart services. `--check`/`--dry-run` are read-only. |
| `sudo ak start [component] [--wait]` | Yes | Start through systemd; `--wait` blocks until containers are running. || `sudo ak start [component]` | Yes | Start through systemd; first start builds images. |
| `sudo ak stop [component]` | Yes | Stop through systemd; keep data and enablement. |
| `sudo ak restart [component]` | Yes | Restart after configuration changes. |

\* The Docker socket may still deny access to a non-root user. The CLI reports
the failure; it does not silently claim success.

Components are `aegis`, `kraken` or `all` (the default). The command and
component can be written in either order:

```bash
sudo ak start
sudo ak start kraken
sudo ak kraken restart
ak status all
```

## Exit status

| Code | Meaning |
|---|---|
| `0` | The requested operation succeeded. |
| `1` | A unit, container, port or file operation failed. |
| `2` | Invalid command, component or option. |

`ak doctor` returns `1` when a required check fails, so it can gate a script:

```bash
ak doctor || exit 1
```

The `Resources:` section reports host RAM, the Docker engine limit and live
container usage. Inside WSL2 that figure is the VM ceiling shared by every
distribution (`memory=` in `%USERPROFILE%\.wslconfig`), not the memory Aegis
requested; see
[OS_COMPATIBILITY.md](OS_COMPATIBILITY.md#5-docker-desktop-memory-on-windows).

## What `start` actually does

`ak start aegis` calls `systemctl start --no-block aegis.service`. The unit:

1. runs `/usr/local/lib/aegis/build-server.sh`;
2. builds the Compose images on the first start or after a package upgrade;
3. runs `docker compose up -d --remove-orphans`;
4. stays enabled for the next boot.

The first build needs network access to the base-image registries and can take
several minutes. `ak status` shows the unit, while `ak ps` and `ak logs` show the
containers. Installing the package does not create a desktop icon because the
server is a headless web service.

### Waiting for readiness

`ak start --wait` starts the unit synchronously and then polls
`docker compose ps --status running`: it returns 0 only when the component has at
least one running container and no container reports `starting` or `unhealthy`.
`--timeout SECONDS` defaults to 300 and applies per component; a timeout exits 1
and prints the `ak ps` / `ak logs` commands to run next.

Without `--wait` the command returns as soon as systemd queued the unit, because
a first start can spend several minutes building images. On Windows `ak start`
already polls the same way (`docker compose up -d`, then running containers are
checked); `--wait` is accepted there for scripts shared with Linux, and
`--no-wait` restores the immediate return. Neither platform treats a one-shot
service that exits 0 (database init, sandbox image loader) as a failure.

## Windows: server MSI and endpoint MSI

Windows has two separate MSIs. Do not mix them up:

| MSI | Installs | `ak` | Starts before login? |
|---|---|---|---|
| `aegis-server-<version>-x64.msi` | Aegis-only payload, dashboard and `ak` | Yes | No. Docker Desktop is per-user; run `ak start` after login. |
| `kraken-server-<version>-x64.msi` | Kraken-only payload and `ak` | Yes | No. Same Docker Desktop boundary. |
| `aegis-suite-<version>-x64.msi` | Aegis and Kraken together, dashboard and `ak` | Yes | No. Same Docker Desktop boundary. |
| `aegis-agent-<version>-x64.msi` | `aegis-agent.exe`, optional ETW helper and the `AegisAgent` service | No | Yes, as a Windows service. |

The server MSIs install under their own root (`Aegis Server`, `Kraken Server`
or `Aegis Suite`) and add `...\bin` to the machine `PATH`, so a new PowerShell
can run `ak`. Aegis and suite ask for the public FQDN, ACME email and local
dashboard port in the wizard. Silent installs can pass the same properties:

```powershell
msiexec /i .\aegis-server-4.3.0-x64.msi /qn `
  AEGIS_DOMAIN=soc.example.com ACME_EMAIL=ops@example.com AEGIS_UI_PORT=3005
ak help
ak configure
ak start              # elevated PowerShell
ak url
```

The first `ak start` generates `C:\ProgramData\Aegis\server.env` with random
secrets, builds the images and starts Docker Compose. It requires Docker Desktop
and an elevated PowerShell because the env file is restricted to Administrators
and SYSTEM. `ak ps`, `ak logs`, `ak status`, `ak url` and `ak doctor` are the
read-only commands; `ak start`, `ak stop`, `ak restart` and `ak configure` need
Administrator.

The backend runs on Windows through Docker Desktop; the Linux and Windows server
packages share the same Compose source. Linux containers need the Linux kernel, so on Windows the engine can only run
inside a VM: Docker Desktop owns that WSL2 VM, which is why it is a per-user
application and not a service. On Linux `dockerd` is native and systemd owns it.
Everything that is ours is still native Windows: the MSI, `ak.ps1`, the
FQDN/ACME/port wizard, env generation, ACLs, registry entries and `PATH`.

The **only** remaining parity difference is boot timing: the Linux package owns
a systemd unit and can start at boot; the Windows packages cannot create a
per-machine pre-login container service with Docker Desktop. `ak start`, a
scheduled task at logon, or Docker Desktop's own startup are the supported
Windows bring-up paths. A true pre-login service requires a per-machine
container runtime or a native Windows port, not a cosmetic MSI change. That work
is tracked in [the roadmap](ROADMAP_LIVE_VALIDATION.md).

### Command differences between Linux and Windows

The command names, components and exit codes are identical, so shared scripts
keep working. The mechanisms behind them differ, and the CLI does not pretend
otherwise:

| Area | Linux (deb/rpm) | Windows (server MSI) |
|---|---|---|
| State read by `ak status` | `systemctl is-active` + `is-enabled` for the unit | Docker containers of the Compose project; there is no unit |
| `ak start` timing | Returns after `systemctl start --no-block`; `--wait` polls the containers | Polls until a container runs and none is starting/unhealthy; `--no-wait` returns immediately |
| Boot | Unit enabled at install, containers are `restart: unless-stopped` | No pre-login service; run `ak start` after logon or a logon task |
| `ak stop` | Stops the unit; it stays enabled for the next boot | Stops the Compose containers; `ak start` is the next bring-up |
| `ak configure` | `--domain/--email/--port/--public-url`, `--restart` | Same options plus `--no-restart` |
| `ak update` artifact | `.deb` packages (`aegis`, `kraken`, suite) installed with apt/dpkg | The edition MSI installed with `msiexec`; `--from` also accepts a local `.msi` |
| `ak update --from` | Directory or URL, and requires `--version` | Directory, local MSI or URL; the version can be inferred from the MSI name |
| `ak doctor` | systemd, unit enablement, env file mode `0600`, Docker, memory | Docker Desktop, Compose, env file, dashboard port, elevation, memory |
| Privileges | `sudo` for start/stop/restart/configure/update | Elevated PowerShell for the same commands |
| `ak version` | CLI version plus `dpkg-query` package versions | CLI version, edition and the installed server version |

Both platforms verify a SHA-256 sidecar before installing an update and refuse a
downgrade without `--allow-downgrade`. On Windows the update must match the
installed edition (Aegis Server, Kraken Server or Aegis Suite); on Linux the
edition is derived from the installed packages, including the `aegis-suite`
metapackage.

The endpoint MSI still accepts `BRAIN_URL=https://...` for a custom server
origin; that property configures the agent, not the server dashboard.

## Update and version selection

`ak update` installs a published release package, which updates both the CLI and
the server payload; the post-install lifecycle rebuilds changed images. It is
explicit, never automatic. `--latest` selects the latest non-prerelease
release; `--version X.Y.Z` pins one. The updater verifies the SHA-256 sidecar
before apt/dpkg or `msiexec`, preserves the FQDN/ACME/port settings, and
restarts the stack unless `--no-restart` is given.
`apt`/`dpkg` run non-interactively (`DEBIAN_FRONTEND=noninteractive`, conffile
`--force-confdef`/`--force-confold`), so a remote update never stops on a
debconf or conffile question and the existing env files are not rewritten.

```bash
ak update --check
ak update --version 4.3.0 --yes
ak update --version 4.2.1 --allow-downgrade --yes
```

Downgrades require a verified database backup because migrations are not
reversed automatically. Only the current and previous minor lines receive
fixes; older artifacts remain installable while they exist but are EOL. The
full policy is in [RELEASE_POLICY.md](RELEASE_POLICY.md).

## Troubleshooting

```bash
ak doctor
ak status
systemctl status aegis --no-pager
journalctl -u aegis -n 100 --no-pager
ak url
```

Common failures:

- **`docker compose v2 not available`**: install the Compose v2 plugin; the
  Windows Docker CLI shim inside WSL is not sufficient.
- **Docker daemon not reachable**: start Docker Engine or Docker Desktop and
  ensure the current user can access the socket.
- **Port already in use**: `sudo ak configure --port <free-port>` while the
  unit is stopped, then `sudo ak restart aegis`.
- **Dashboard loads but login fails**: use the configured HTTPS origin or set
  `AEGIS_COOKIE_SECURE=false` only for an explicit local HTTP deployment.
- **Endpoint MSI installed, no `ak`**: expected. Install `aegis-server`,
  `kraken-server` or `aegis-suite` on the server; `ak` belongs to the server
  packages, not the endpoint agent.

## Related documents

- [Packaging](PACKAGING.md)
- [Operations](OPERATIONS.md)
- [Persistence](PERSISTENCE.md)
- [Pilot runbook](PILOT_RUNBOOK.md)
