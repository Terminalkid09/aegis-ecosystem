# Kraken — deception and honeypot lab

Kraken is the optional deception service in the Aegis ecosystem. It is built for
controlled labs and pilots, not for exposing a default stack directly to the
Internet. It has its own database, Redis, users, session cookie scope and SSO
assertion; the Brain receives only signed events and a read-only view.

## What runs

| Component | Role |
|---|---|
| `aegis-kraken` | FastAPI application, own PostgreSQL/Redis, event/alert/incident API, reports, SSO. No Docker socket. |
| `aegis-kraken-broker` | The only process that talks to the Docker daemon. Creates ephemeral sandboxes with a fixed policy. Internal-only, non-root, capability-dropped. |
| `aegis-kraken-sensors` | Six deception listeners. No Docker socket; asks the app/broker for a sandbox over the internal HTTP API. |
| `aegis-kraken-rdp` | Real xrdp + XFCE endpoint with disposable weak decoy accounts. No host filesystem or Kraken secrets. |
| `aegis-kraken-db` / `aegis-kraken-redis` | Private state; never published to the host. |

## Sensors and real engines

The base profile keeps every listener internal, but all six are enabled by
default; exposure is still an explicit overlay. SMB and RDP use unprivileged
container ports (`4445`/`33890`), so a client connecting to host 445/3389 is
proxied by Compose without requiring a privileged sensor process.

| Protocol | Engine | Behavior |
|---|---|---|
| SSH | `asyncssh` | OpenSSH-compatible banner, accepts credentials, interactive shell backed by the sandbox; deterministic realistic fallback if the broker is down. |
| HTTP | asyncio | Virtual hosts, portal/OWA/RDWeb pages, Apache-style 403/404, recon paths, method/path/header/body capture. |
| FTP | `pyftpdlib` | Real login, PASV, LIST/RETR/STOR/DELE/MKD, decoy filesystem, upload SHA-256. |
| Telnet | asyncio + sandbox | Ubuntu-style login and interactive shell; same fallback shell as SSH. |
| SMB | `impacket` | SMB2 share, authentication, list/read/write and NetNTLMv2 capture. Relay/signing attacks are not implemented by design. `KRAKEN_SMB_ENGINE=raw` keeps the old negotiation-only probe. |
| RDP | `xrdp` + XFCE | Real RDP session with `administrator`, `admin` and `kraken` decoy accounts. xrdp auth logs are container logs, not yet Aegis-ingested. |

The SMB and RDP statements are deliberately narrower than “full enterprise
protocol implementation”: there is no SMB relay, no RDP credential relay and no
xrdp log shipper in this branch. The lab/telemetry gaps are tracked in
`docs/ROADMAP_LIVE_VALIDATION.md`.

## Exposure model

The base `docker-compose.yml` keeps every sensor on the internal network. It
does **not** publish SSH, FTP, Telnet, SMB or RDP. This is intentional: a normal
pilot must not inherit six exposed ports.

For a disposable honeypot host, use the explicit overlay:

```bash
KRAKEN_HONEYPOT_BIND_IP=0.0.0.0 \
KRAKEN_SENSOR_PROTOCOLS=ssh,http,ftp,telnet,smb,rdp \
KRAKEN_SSH_PORT=22 KRAKEN_HTTP_PORT=80 KRAKEN_FTP_PORT=21 \
KRAKEN_TELNET_PORT=23 KRAKEN_SMB_PORT=445 KRAKEN_RDP_PORT=3389 \
KRAKEN_FTP_PASV_ADVERTISE_HOST=<host-ip> \
docker compose --profile kraken \
  -f docker-compose.yml -f docker-compose.kraken-honeypot.yml up -d
```

- The overlay binds to `127.0.0.1` unless `KRAKEN_HONEYPOT_BIND_IP=0.0.0.0` is
  set explicitly.
- Use a dedicated host/VLAN with no sensitive data and egress filtering.
- If a standard port is already in use, change `KRAKEN_*_PORT` rather than
  exposing an obvious high port just to make it fit.
- `KRAKEN_FTP_PASV_ADVERTISE_HOST` is the address the client can reach; the
  container's `172.x` address is not routable from the attacker. The passive
  range defaults to `30000-30009` and must match the published range.

## Sandbox

Sandboxes are created by the broker, not by the web process:

- `network_mode: none`;
- read-only root filesystem;
- non-root `sandbox` user;
- all capabilities dropped;
- bounded CPU/RAM/PIDs;
- ephemeral lifetime and explicit destroy.

The broker needs the Docker socket to create these containers. It is not
published, and Compose applies CPU/RAM/PID limits, `no-new-privileges` and
`cap_drop: ALL`. This reduces, but does not eliminate, the risk of a
Docker-socket compromise; treat the broker as a high-privilege component.

On Linux the socket is usually owned by a non-root `docker` group. Export its
GID before starting the profile, otherwise the non-root broker cannot open it:

```bash
export DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)
```

Docker Desktop may use GID 0. The CI derives the same value instead of
hard-coding it. The broker must not be switched back to root just to bypass
this permission.

## Testing

```bash
# Unit tests: 108 passed in the 4.3 audit
pytest tests/unit -q --no-cov

# Integration tests: 46 passed in the 4.3 audit, separate process
pytest tests/integration -q --no-cov

# Total: 154 passed
```

Unit and integration must run in separate processes: together they share the
session-scoped SQLite fixture and produce false failures. CI runs them
separately. The local audit used an isolated Python 3.13 venv; CI uses 3.11.

The live audit also verified 13 attack events, 13 deception alerts, 4
incidents, signed outbox delivery **1/1**, SSO exchange **200**, replay **401**
and all Kraken pages **200**.

## Security notes

- Secrets are required; the app refuses placeholders and weak values.
- The app runs as `kraken`, not root.
- The broker is now non-root; the Docker socket group is added explicitly.
- Sensors do not receive the Docker socket.
- Honeypot ports are internal by default; exposure is an explicit overlay.
- Source-IP attribution on Docker Desktop collapses to the bridge gateway
  (`172.21.0.1`). Validate source-IP preservation on a Linux host before using
  GeoIP or attribution in a real lab; this is part of the advanced-lab roadmap.

## License

Kraken is licensed under **MIT** (`services/kraken/LICENSE`). The Aegis
ecosystem root is **AGPL-3.0-only**; see the root `LICENSE`, `NOTICE` and
`THIRD_PARTY_NOTICES.md`. The two notices are intentionally separate and must
not be presented as one license.
