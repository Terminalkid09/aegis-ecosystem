# Persistence and reboot behavior

Status: 2026-11-22.

This page separates three different guarantees that are often confused:

1. the agent service starts at boot;
2. the service restarts after a crash;
3. the Aegis/Kraken containers return when the Docker engine starts.

## Matrix

| Component | Starts at boot | Restarts after crash | Notes |
|---|---|---|---|
| Windows agent, MSI | Yes, `AegisAgent` is `Start="auto"` | Yes, three restarts 5 s apart | Token must exist before the service can enroll. Uninstall removes the service. |
| Windows agent, one-liner | Yes, `New-Service -StartupType Automatic` | Yes, `sc.exe failure ... restart/5000` | Requires an elevated PowerShell and a short-lived token. |
| Linux agent, deb/RPM | Yes, the package enables `aegis-agent.service` | Yes, the unit uses `Restart=always` | The package enables but does not start the unit; provision the token first. |
| Linux agent, one-liner | Yes, `systemctl enable --now aegis-unified.service` | Yes, `Restart=always` | The generated unit is independent from the package unit. |
| OpenWrt agent, ipk | Yes, `postinst` enables the procd service | Yes, `procd_set_param respawn` | Only when the router is an OpenWrt host with the ipk installed. |
| Aegis platform package (`aegis`) | Yes, `aegis.service` is enabled | Yes, containers use `restart: unless-stopped`; the oneshot unit is the boot bring-up | Complete stack including dashboard. First start builds images; `/etc/aegis/server.env` is generated once. |
| Kraken package (`kraken`) | Yes, `kraken.service` is enabled | Yes, same model | Complete standalone Kraken stack; separate package, database, Redis and secrets. |
| Aegis core containers | Yes, when the Docker daemon starts | Yes, `restart: unless-stopped` | Postgres, Redis, Brain, Link, frontend, Caddy and backup. |
| Kraken profile containers | Yes, when the Docker daemon starts | Yes, `restart: unless-stopped` | App, sensors, broker, DB and Redis. One-shot init/sandbox-image helpers are intentionally `restart: "no"`. |
| `deploy/kraken-lab/` overlay | No | No | It is a single-host lab harness; each node is deliberately `restart: "no"`. |
| A router that only routes packets | Not applicable | Not applicable | Aegis does not install a component on a plain router; only the OpenWrt ipk path applies. |

## Privileges: one elevation, not one per boot

The Windows MSI is per-machine and installs `AegisAgent` as a `LocalSystem`
service. The one-time `msiexec`/elevated PowerShell is the only UAC prompt; the
service manager starts it at boot with no interactive prompt and no dependency
on the logged-in user. The generated one-liner uses the same service model.

Linux deb/RPM installs as root, enables `aegis-agent.service`, and systemd
starts it as root at boot. The Linux one-liner does the same through
`aegis-unified.service`. OpenWrt's procd service is enabled by the package and
runs as root. A server or router has no UAC prompt because there is no Windows
desktop; the install is performed once by the administrator/package manager.

Docker Desktop is the exception: it is a per-user desktop application. The
Windows server MSI installs `ak` and the Compose payload, but the first bring-up
is `ak start` after sign-in; `scripts/install-autostart.ps1` can start Docker
Desktop from the current user's Run key. Neither provides pre-login
availability. Use Linux Docker Engine for an unattended server.

## Crash simulation (not a reboot)

These checks prove the service supervisor recovers from a killed process. They
do **not** prove host boot and do not replace a reboot test. Run them only on a
test host.

Windows, elevated PowerShell:

```powershell
$p = Get-Process aegis-agent -ErrorAction Stop
Stop-Process -Id $p.Id -Force
Start-Sleep -Seconds 8
Get-Service AegisAgent
Get-Process aegis-agent
```

Linux:

```bash
systemctl kill -s KILL --kill-who=main aegis-agent
sleep 8
systemctl is-active aegis-agent
systemctl show -p MainPID --value aegis-agent
```

OpenWrt:

```sh
kill -9 "$(pidof aegis-agent)"
sleep 8
pidof aegis-agent
```

### WSL2 lab host: reset the shared VM

A long-running Docker Desktop WSL distro can leave the shared WSL utility VM
wedged. The symptom is `Wsl/Service/CreateInstance/HCS_E_CONNECTION_TIMEOUT`
when starting **any** other distro (both Ubuntu and Kali failed here) while
`docker-desktop` remains running. It is a WSL host failure, not an agent
package failure.

Recovery and diagnosis:

```powershell
wsl --shutdown
wsl --terminate Ubuntu
wsl -d Ubuntu -- uname -r
```

On 2026-11-22 the shutdown restored Ubuntu in 9 seconds with
`networkingMode=mirrored` unchanged; the distro VHD was healthy. Enable systemd
in `/etc/wsl.conf` (`[boot]` `systemd=true`) before testing service persistence.
`wsl --shutdown` also stops Docker Desktop's WSL backend; verify
`docker compose ps` and the containers' health after restarting Docker Desktop.

The repository check is:

```bash
python scripts/persistence_check.py --live-linux
python scripts/persistence_check.py --live-windows
python scripts/persistence_check.py --containers
```

`--live-windows` reports `AegisAgent is not installed` instead of pretending a
process is a service. That distinction matters: a manually started
`aegis-agent.exe` does not survive a reboot.

## Docker host prerequisite

Compose restart policies do **not** start the Docker daemon. They only tell the
daemon what to do with an existing container.

### Linux server

```bash
sudo systemctl enable --now docker
systemctl is-enabled docker
docker compose ps
```

`docker compose up -d` must have created the containers at least once. After
that, an enabled Docker daemon and `restart: unless-stopped` are sufficient for
a reboot. If the operator explicitly ran `docker compose stop`, the containers
stay stopped by design.

### Windows PC

Docker Desktop is a per-user desktop application, not a server service. Enable
its login startup explicitly:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-autostart.ps1
```

The script adds the current user's `Docker Desktop.exe` to the `Run` key. It is
reversible with `-Remove`. The Aegis containers then return when the Docker
engine is ready, because they use `restart: unless-stopped`.

This covers a workstation after the user signs in. It does **not** provide
pre-login availability. For an unattended server, use Linux with Docker Engine
enabled at boot, or an operator-managed Windows service with a supported
container runtime; Docker Desktop is not a substitute for that.

The reason is architectural, not a missing flag: Linux containers need the Linux
kernel, so on Windows the engine runs inside a VM that Docker Desktop owns as a
per-user application. There is no `docker.service` equivalent to enable with
`sc.exe`. A pre-login path would need a service wrapper that starts the WSL
distribution and `dockerd` (or a Hyper-V Linux VM) and is tracked as Phase 5 in
[ROADMAP_LIVE_VALIDATION.md](ROADMAP_LIVE_VALIDATION.md).

## Agent verification

Windows:

```powershell
Get-Service AegisAgent
sc.exe qc AegisAgent
sc.exe qfailure AegisAgent
```

The expected startup type is `AUTO_START`, and the failure actions must contain
`RESTART`. The MSI and the one-liner both configure them.

Linux:

```bash
systemctl is-enabled aegis-agent
systemctl show -p Restart aegis-agent
```

The expected values are `enabled` and `Restart=always`. The one-liner uses
`aegis-unified.service` instead of the packaged unit.

Server packages:

```bash
systemctl is-enabled aegis kraken
systemctl show -p Restart --value aegis
systemctl show -p Restart --value kraken
```

The units are oneshot boot bring-up; `Restart` is empty by design, while the
containers carry `restart: unless-stopped`. Both units must be `enabled`.
They run as `root` because they need the Docker socket and host-level bring-up;
the generated `/etc/aegis/*.env` files are root-owned `0600`. Their first start
builds images and needs network access.

OpenWrt:

```sh
/etc/init.d/aegis-agent enabled && echo enabled
/etc/init.d/aegis-agent status
```

## Container verification

```bash
docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' \
  aegis-brain aegis-kraken aegis-kraken-sensors aegis-kraken-broker
```

Expected: `unless-stopped` for long-running services. A container with
`restart: "no"` is intentionally not a persistence guarantee: the Kraken lab
overlay and one-shot helpers fall into this category.

## What is not claimed

- A real host reboot is not simulated by `docker restart`; the host-level
  Docker autostart must be checked on the target.
- A plain router has no Aegis service to restart. Only an OpenWrt device with the
  ipk is in scope.
- A local administrator can stop the agent, Docker or the containers. Persistence
  is availability, not tamper-proofing.
- Windows Server live validation and Linux bare-metal validation remain release
  gates; this document records the configured behavior, not a new certification.
- The server packages' first start needs network access to build OCI images; an
  offline/prebuilt image bundle is not shipped in 4.3.
- A real host reboot with the server packages installed is still required. This
  host verified package layout, `0644` units, `0600` secrets and enablement;
  `systemd-analyze verify` only reports the missing `docker.service` because
  Docker Desktop is not integrated into this WSL distro and has no Docker CLI or
  socket there. The units now use `Wants=docker.service`, so a Docker Desktop
  WSL socket can start them when the CLI is present. A host with Docker Engine
  must still start the unit and reboot.
