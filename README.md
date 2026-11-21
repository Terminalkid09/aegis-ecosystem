<h1 align="center">Aegis Ecosystem</h1>
<p align="center">
  <strong>Open-source SOC-in-a-box</strong><br/>
  Endpoint detection, multi-source SIEM, deterministic detection, SOAR and deception — in one local-first stack.
</p>

<p align="center">
  <a href="https://github.com/Terminalkid09/aegis-ecosystem/actions/workflows/ci.yml"><img src="https://github.com/Terminalkid09/aegis-ecosystem/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <img src="https://img.shields.io/badge/python-3.15-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.15" />
  <img src="https://img.shields.io/badge/go-1.27-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go 1.27" />
  <img src="https://img.shields.io/badge/react-19-61dafb?style=flat-square&logo=react&logoColor=white" alt="React 19" />
  <img src="https://img.shields.io/badge/postgres-16-4169E1?style=flat-square&logo=postgresql&logoColor=white" alt="PostgreSQL 16" />
  <img src="https://img.shields.io/badge/docker-compose-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker Compose" />
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#platform-support">Platforms</a> •
  <a href="#security-identity--secrets">Security</a> •
  <a href="#documentation">Docs</a> •
  <a href="#verification">Verification</a>
</p>

---

## Overview

Aegis is a local-first XDR/SIEM platform for security labs, controlled pilots and small teams. A single stack combines endpoint telemetry, log ingestion, Sigma/correlation detection, incident triage, response playbooks, static analysis and a deception service.

The design goal is **honest operation**: deterministic detections, explicit degradation when a kernel source is unavailable, no silent fallback to a fake success, and no secret with a public default.

> **Scope.** 4.3.0 is a controlled-pilot release, not production GA. Detection is deterministic (rules, Sigma, correlation and heuristics; no ML). Single-node Compose is the supported deployment; the HA overlay is documented separately.

## Capabilities

| Area | What is included |
|---|---|
| **Endpoint** | One unified Go agent with explicit `full`, `sensor` and `endpoint` modes; process lineage, persistence, masquerading and security-control tampering detection; signed OTA updates. The mode selects capabilities, not a second agent. |
| **Kernel telemetry** | eBPF on Linux (`sched_process_exec`, `do_exit`, TCP state) and ETW kernel providers on Windows; no kernel driver and no Windows driver signing. |
| **SIEM** | Syslog, Windows Event Log, Zeek, Suricata, nginx/Squid, pfSense/iptables; normalised events and source-health visibility. |
| **Detection** | Static rules, custom AND/OR rules, Sigma with fail-loud exclusions, threshold/sequence correlation and MITRE ATT&CK mapping. |
| **SOAR** | Playbook triggers, 12 action types, bounded command queue with ack, visibility timeout and DLQ. |
| **Analysis** | PE/ELF/Mach-O/Office/PDF/archive/APK analysis with YARA, entropy, imports and IOC extraction. |
| **Deception** | Optional Kraken profile: deception sensors, campaigns, Lab, read-only Aegis view and delegated SSO. The base profile keeps sensors internal; the honeypot overlay is an explicit lab-only exposure. |

YARA is optional and fail-soft: the engine is present only when the platform has
a `yara-python` wheel, and the API reports the missing engine instead of silently
skipping it. Its value depends on the SOC's rules, not on the dependency alone.
Signed feeds are opt-in and fail-closed: rules are imported only from a bundled
Ed25519-signed manifest with a configured public key, and feed-managed rules
cannot overwrite local rules. Aegis Total exposes match provenance, severity and
a confidence signal instead of a flat boolean. See [YARA feeds](docs/YARA_FEEDS.md).

## Quick Start

Requirements: **Docker Desktop running** and **Python 3.15+**. Endpoint agents are installed separately from the dashboard.

```bash
git clone https://github.com/Terminalkid09/aegis-ecosystem.git
cd aegis-ecosystem
python scripts/setup.py
```

`setup.py` generates a `.env` with random secrets, starts the stack, waits for readiness, bootstraps the first admin and runs the API smoke test. The admin password is printed **once** and is not written back to `.env`.

Update without touching the database volume:

```bash
python scripts/setup.py update
```

| Profile | Command | Notes |
|---|---|---|
| **Lab** | `docker compose up -d --build` | Internal TLS, localhost ports, local login. |
| **Pilot** | `docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.mtls.yml up -d --build` | mTLS, real secrets and `BACKUP_PASSPHRASE`. |
| **Observability** | `docker compose -f docker-compose.yml -f docker-compose.observability.yml --profile observability up -d --build` | Lab-only Prometheus and Grafana; not a production monitoring stack. |
| **Kraken** | `docker compose --profile kraken up -d --build` | Deception stack with sensors internal by default. For an isolated honeypot lab, add `-f docker-compose.kraken-honeypot.yml` and set `KRAKEN_HONEYPOT_BIND_IP=0.0.0.0`; the signed Brain ingest path remains opt-in with `KRAKEN_INGEST_ENABLED=true`. |

### Public domain and TLS

Caddy reads `AEGIS_DOMAIN` and `ACME_EMAIL` from `.env`. The default
`AEGIS_DOMAIN=aegis.local` uses Caddy's internal CA and is lab-only. For a real
deployment set the public FQDN (DNS A/AAAA to the host, ports 80/443 reachable),
a real ACME email, and keep `ALLOWED_ORIGINS`/`PUBLIC_BASE_URL` on the same host:
Caddy obtains and renews a Let's Encrypt certificate automatically. No domain or
certificate is hardcoded in the repository.

The default dashboard is `http://localhost:3000`; the Brain API is `http://localhost:8000`. Never expose the lab stack directly to the Internet.

Caddy is the production TLS/reverse-proxy edge when it runs with a real FQDN,
ACME and the mTLS overlay; it is not a complete HA or monitoring solution. Run
at least two replicas behind an external load balancer for availability, and
monitor certificate renewal and upstream health separately.

## Platform Support

| Platform | Kernel telemetry | Status |
|---|---|---|
| **Windows 11 22H2+** | ETW `Kernel-Process` 1/2 and `Kernel-Network` TcpIp event 12 | **Live validated elevated** on this host: 95 events (45 created, 47 exited, 3 connections). The helper has a `requireAdministrator` manifest and a runtime admin check; non-admin execution exits 2 without starting. |
| **Windows Server 2022/2025** | Same ETW consumer | Code-compatible; live Server validation remains a lab task. |
| **Linux** | eBPF CO-RE probes with ring buffer | **WSL2 Ubuntu and Kali validated**. Bare-metal Ubuntu/Debian/RHEL validation remains pending. Requires kernel >= 5.8, BTF and `CAP_BPF`/`CAP_PERFMON`. |
| **macOS** | None in the unified 4.3 agent; legacy Guard polling is not in the bundle | **Not supported for endpoint telemetry.** No EndpointSecurity entitlement or System Extension. Darwin builds/tests are in CI; no live Mac hardware is available. |

The kernel source is not a driver. Linux eBPF and Windows ETW are user-mode-orchestrated kernel telemetry; a Windows kernel driver would add signing, WHQL and crash-support costs. See [Kernel and driver feasibility](docs/KERNEL_AND_DRIVERS.md) and [OS compatibility](docs/OS_COMPATIBILITY.md).

## Security: Identity & Secrets

- **Login:** HttpOnly cookie session, CSRF origin check, per-account throttling, remember-me with opaque rotated tokens.
- **Users & Roles:** admin-only UI and API; server-side last-admin guard (409); local break-glass admin is preserved.
- **OIDC / SSO:** Authorization Code + PKCE, signed state/nonce, JWKS verification, group-to-role mapping, auto-provisioning and email verification. The SPA probes `/auth/me` on load, so an HttpOnly session created by the IdP callback is visible immediately.
- **Secrets:** `NAME_FILE`, `AEGIS_SECRETS_DIR`, or HashiCorp Vault KV v2; files win over plain env values and Vault only fills missing values. Missing, empty or unreadable secrets fail closed.
- **No public defaults:** production startup rejects short secrets and known placeholder markers. Compose requires the core secrets instead of defaulting to a known password.

Details: [Secrets](docs/SECRETS.md) · [OIDC](docs/OIDC.md) · [Threat model](docs/THREAT_MODEL.md) · [Operations](docs/OPERATIONS.md).

## Verification

Latest local verification: **2026-11-21**.

| Check | Result |
|---|---|
| Brain pytest against disposable PostgreSQL + real Redis | **902 passed, 4 skipped** (the skips include YARA engine cases because `yara-python` is unavailable on Python 3.15/Windows; a dedicated CI job runs them on Python 3.12) |
| Auth hardening, live through Caddy | **PASS**; password reset revokes old JWT and remember devices, SSO-only rejects local login/registration (**403**), OIDC callback without state fails closed, HSTS only on HTTPS, session cookie **HttpOnly/Secure/SameSite=strict** |
| Command queue on real Redis | **8 passed**, including redelivery and restart recovery |
| Kraken pytest | **154 passed** |
| Frontend production build | **PASS** |
| Frontend lint | **0 errors, 24 warnings** |
| Playwright pages/session/smoke/Kraken through Caddy | **13 passed**; the `users` spec assumes a single-admin database and was not used for this local run |
| Playwright OIDC against Keycloak 26.0.7 | **2 passed** |
| ETW live elevated | **PASS**, 95 events; non-admin **exit 2** |
| WSL2 Ubuntu / Kali eBPF | **PASS**; benchmark **300/300**, zero lost events |
| macOS Darwin build (amd64/arm64) | **PASS locally**; `macos-latest` job added to CI; no live hardware |
| File secrets + real Vault KV v2 | **PASS**, including precedence and fail-closed cases |
| Clean install from Git clone, core + Kraken | **PASS**; API smoke **21/21**; Kraken healthy |
| Unified capability modes | `full`, `sensor`, `endpoint` via token/installer/`--mode`; one `agent_type=unified` record in every mode | **PASS locally** |
| Docker hardening | Compose valid, CPU/RAM/PID limits, `no-new-privileges`, non-root broker, sensors internal by default | **PASS locally** |
| Branch/PR CI | CI now runs on `dev`, `main`, `feat/**`, pull requests and tags; release job remains tag-only | **PASS — run 44916543187 (non-release jobs); tag job not run** |

Not verified locally: hosted CI/tag workflow, bare-metal Linux, Windows Server live, and macOS live. These are release gates, not claims. See [Release gate 4.3](docs/RELEASE_GATE_4.3.md).

## Documentation

| Document | Purpose |
|---|---|
| [OS compatibility](docs/OS_COMPATIBILITY.md) | Supported versions, sensors, fallbacks and live evidence. |
| [Kernel and driver feasibility](docs/KERNEL_AND_DRIVERS.md) | Why eBPF/ETW are not universal, and the real cost of a signed driver. |
| [Secrets](docs/SECRETS.md) | File, Docker/Kubernetes and Vault configuration. |
| [OIDC](docs/OIDC.md) | SSO configuration, role mapping and break-glass. |
| [Operations](docs/OPERATIONS.md) | Install, upgrade, backup/restore and PKI. |
| [Pilot runbook](docs/PILOT_RUNBOOK.md) | Pilot deployment and acceptance. |
| [Release gate](docs/RELEASE_GATE_4.3.md) | What is green, what remains, and allowed claims. |
| [Threat model](docs/THREAT_MODEL.md) | Assets, trust boundaries and mitigations. |
| [Benchmarks](docs/BENCHMARK.md) | Load methodology and measured numbers. |
| [YARA feeds](docs/YARA_FEEDS.md) | Signed rule bundles, key rotation and fail-closed import. |

## Development

```bash
# Brain tests (disposable database and Redis required)
# conftest derives AEGIS_TEST_REDIS_URL (DB 15, same auth) from REDIS_URL so
# queue tests never flush the application's DB 0.
cd aegis-brain
python -m pytest tests/ -q

# Frontend
cd frontend && npm ci && npm run build && npm run lint

# Playwright (live stack, admin credentials from env)
E2E_NO_SERVER=1 E2E_BASE_URL=http://localhost:3000 \
E2E_EMAIL=... E2E_PASSWORD=... npx playwright test

# Go agent
cd aegis-agent && go test -count=1 ./...
```

The repository is a monorepo: `aegis-brain` (FastAPI), `aegis-agent` (Go), `aegis-ebpf` (eBPF/ETW), `frontend` (React), `aegis-link` (Spring Boot) and `services/kraken` (deception). CI runs lint, secret scan, tests, Trivy, SBOM and the Compose E2E gate; the release is cut only after the hosted tag workflow is green.

## License

Aegis Ecosystem is licensed under **AGPL-3.0-only** (the root is not Apache). See [LICENSE](LICENSE) and [NOTICE](NOTICE). **Kraken** is a separately licensed **MIT** component: see [services/kraken/LICENSE](services/kraken/LICENSE) and its [README](services/kraken/README.md#license). The MIT component is distributed inside the AGPL bundle and keeps its own notice; it does not relicense the rest of the repository. The name and logo are governed by [TRADEMARK.md](TRADEMARK.md). Security reports: [SECURITY.md](SECURITY.md).

<p align="center"><strong>Authorized use only.</strong> Aegis is a defensive platform for systems you own or have explicit written permission to monitor.</p>
