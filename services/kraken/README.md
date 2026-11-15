# Kraken — Honeypot Intelligence Platform

Multi-protocol honeypot system with interactive sandbox analysis, real-time attack detection, GeoIP enrichment, and full monitoring stack. Designed for threat intelligence gathering in production environments.

## Features

| Capability | Implementation |
|---|---|
| Multi-protocol sensors | SSH (asyncssh), HTTP, FTP, Telnet — fully passive |
| Interactive sandboxes | Ephemeral Docker containers with auto-destroy watchdog |
| GeoIP enrichment | Country, city, coordinates, ASN, ISP via MaxMind |
| Real-time alerts | Telegram bot notifications on every hit |
| Live dashboard | Leaflet world map, Chart.js stats, dark/light theme |
| Export & reporting | CSV, JSON, PDF intelligence reports with ReportLab |
| JWT authentication | Access + refresh tokens, HttpOnly cookies, Redis blacklist |
| Rate limiting | Per-endpoint via SlowAPI + nginx burst limiting |
| Malware capture | Automatic extraction from sandbox diffs, SHA256 hashing |
| Monitoring | Prometheus metrics, Grafana dashboards, Alertmanager |
| Secure by default | Security headers, non-root containers, sandbox isolation |

## Architecture

```
kraken/
├── app/                        # FastAPI backend
│   ├── api/v1/endpoints/       # auth, events, export, containers, health
│   ├── core/                   # config, security (JWT + bcrypt + API key)
│   ├── db/                     # SQLAlchemy async + Redis + token blacklist
│   ├── models/                 # ORM: User, AttackEvent, Command, Credential, MalwareSample
│   ├── schemas/                # Pydantic v2 with strict IP/input validation
│   ├── services/               # GeoIP, Telegram, Docker, ReportLab, SIEM, attack CRUD
│   └── templates/              # Jinja2: login, dashboard, events
├── honeypot/sensors/           # Passive protocol listeners (ssh, http, ftp, telnet)
├── nginx/                      # Reverse proxy with TLS, rate limiting, security headers
├── monitoring/                 # Prometheus, Alertmanager, Grafana configs
├── alembic/                    # Database migrations
├── scripts/                    # Admin creation, demo seeding, backup/restore
├── tests/                      # 65+ unit tests, integration tests
├── docker-compose.yml          # Full production stack (10 services)
├── Dockerfile                  # Non-root user, pinned deps
└── .env.example                # All configurable parameters documented
```

**Network isolation:**
- `kraken_app` — Docker socket access (sandbox mgmt)
- `kraken_sensors` — No Docker socket (sandbox via HTTP API to app)
- `kraken_sandbox` — `network_mode: none`, read-only FS, cap_drop ALL

## Quick Start

### Prerequisites
- Docker + Docker Compose
- Python 3.10+ (for local dev/test)
- MaxMind GeoLite2-City.mmdb → `./data/GeoLite2-City.mmdb` (optional)

### Setup

```bash
cp .env.example .env
```

Edit `.env` and set:
- `SECRET_KEY` — `python -c "import secrets; print(secrets.token_hex(32))"`
- `INTERNAL_API_KEY` — same method

```bash
# Build & start everything
docker compose up --build -d

# Create admin user
docker exec -it kraken_app python scripts/create_admin.py admin <your_password>

# Open https://localhost (dev) or your domain (prod)
```

### Demo data

```bash
docker exec -it kraken_app python scripts/seed_demo.py
```

## API Reference

Full interactive docs at `/api/docs` (proxied through nginx).

### Authentication
- **JWT** — `Authorization: Bearer <token>` or `kraken_token` cookie
- **Internal API Key** — `X-Internal-API-Key` header (sensor → app communication)
- **Endpoints**: `/api/v1/auth/login`, `/api/v1/auth/refresh`, `/api/v1/auth/logout`

### Key endpoints

| Method | Path | Auth | Rate limit |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | — | 10/min |
| `POST` | `/api/v1/auth/register` | — | 5/min |
| `POST` | `/api/v1/events/ingest` | API Key | 200/min |
| `GET` | `/api/v1/events/` | JWT | default |
| `GET` | `/api/v1/events/stats` | JWT | default |
| `GET` | `/api/v1/export/pdf` | JWT | 30/min |
| `DELETE` | `/api/v1/containers/{id}` | Admin/API Key | default |
| `GET` | `/api/v1/health/detailed` | — | — |

## Testing

```bash
# Unit tests (65+ tests, zero external dependencies)
pytest tests/unit/ -v

# All tests (including integration, requires PG + Redis)
pytest

# Lint
ruff check app/ honeypot/ tests/
```

Tests use **SQLite in-memory** and **fake Redis** by default — no external services needed.

## Deployment (Production)

### Requirements
- Linux server with Docker Engine 24+
- 2 GB RAM minimum, 4 GB recommended
- Domain with DNS pointing to server
- GeoLite2-City.mmdb in `./data/`

### Steps

```bash
# 1. Generate strong secrets
python -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python -c "import secrets; print('INTERNAL_API_KEY=' + secrets.token_hex(32))"

# 2. Configure .env
nano .env

# 3. Get SSL certs (Let's Encrypt) into nginx/ssl/
#    — or remove HTTPS from nginx.conf and use your own reverse proxy

# 4. Start
docker compose up -d --build

# 5. Create admin
docker exec kraken_app python scripts/create_admin.py admin <strong_password>

# 6. Set up monitoring
#    Grafana: http://yourdomain:3000 (admin / admin)
#    Import dashboard from monitoring/dashboards/
```

### Backup

```bash
# Manual
docker exec kraken_backup /usr/local/bin/backup.sh

# Automatic: daily at 02:00 (configured in Dockerfile.backup)
```

## Security

- **Secrets validation at startup** — refuses to run with defaults in production
- **Non-root containers** — app runs as `kraken` user, sandbox as `sandbox`
- **Sandbox isolation** — `network_mode: none`, read-only FS, no capabilities, 128MB RAM, 64 pids
- **No Docker socket in sensors** — sensors communicate via authenticated HTTP API
- **JWT blacklist** — tokens revoked on logout via Redis
- **Security headers** — HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection
- **Input validation** — Pydantic v2 with `ipaddress` stdlib, strict length/size limits
- **Rate limiting** — nginx burst + SlowAPI per-endpoint limits

## License

MIT — see LICENSE.
