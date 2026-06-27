# Aegis XDR / SIEM Ecosystem

Aegis is a local XDR/SIEM lab made of four main services:

| Component | Stack | Role |
| --- | --- | --- |
| `aegis-brain` | FastAPI, SQLAlchemy, PostgreSQL, Redis | API, auth, telemetry processing, rules, alerts, VaultX, AI/OSINT endpoints |
| `aegis-link` | Spring Boot | Agent/syslog ingestion gateway; pushes events to Redis |
| `aegis-guard` | Java | Endpoint security agent and mitigation command consumer |
| `NodeTrace` | Python | Host telemetry agent for CPU/RAM/process/users/network flows |
| `frontend` | React | Dashboard for alerts, agents, rules, VaultX, OSINT and AI |

## Architecture

```text
Endpoints / Syslog
       |
       v
Aegis-Link  ---> Redis queue/cache ---> Aegis-Brain ---> PostgreSQL
                                           |
                                           v
                                      React Dashboard
```

## Quick Start

1. Copy the example environment file:

```cmd
copy .env.example .env
```

2. Change the security values in `.env` before using anything beyond local development:

```env
AEGIS_API_KEY=replace-with-a-long-random-value
AGENT_ENROLL_KEY=replace-with-a-long-random-value
JWT_SECRET=replace-with-at-least-32-random-characters
MASTER_KEY_B64=base64-encoded-32-byte-key
REDIS_PASSWORD=replace-with-a-long-random-value
```

Generate `MASTER_KEY_B64` with:

```cmd
openssl rand -base64 32
```

3. Start the platform:

```cmd
docker compose up -d --build
```

4. Open:

- Dashboard: `http://localhost:3000`
- Brain API: `http://localhost:8000`
- Link health: `http://localhost:8080/actuator/health`

On Windows you can also use:

```cmd
aegis.bat
```

## Authentication Model

- **Dashboard**: Bearer JWT after `POST /api/v1/auth/login` or register. Telemetry, rules, VaultX, OSINT (live), and AI require JWT.
- **Agents**: enrollment key at registration, then per-agent Bearer token (NodeTrace) or gateway API key (Aegis-Link).
- **Aegis-Link**: `X-Api-Key` for event ingestion — server-side only, not exposed to the React app.

The global `AEGIS_API_KEY` is for Aegis-Link and automation scripts. It does **not** grant dashboard access.

## Database

`aegis-brain` runs `alembic upgrade head` on startup. The repository includes an initial Alembic revision under `aegis-brain/alembic/versions`.

There is still an optional development fallback, `DB_BOOTSTRAP_CREATE_ALL=true`, that creates missing tables from SQLAlchemy metadata. Leave it disabled in production and use Alembic revisions for schema changes.

## Redis

Redis is password-protected in Docker Compose and all services are configured to use the same `REDIS_PASSWORD`.

If you run Redis outside Compose, make sure `REDIS_URL`, `REDIS_PASSWORD`, and `SPRING_DATA_REDIS_PASSWORD` all point to the same authentication setup.

## Agents

Containerized `aegis-guard` is behind the optional Compose profile:

```cmd
docker compose --profile container-agents up -d --build
```

For real endpoint telemetry, run agents on the host:

```cmd
cd NodeTrace\agents\python
python agent.py
```

```cmd
cd aegis-guard
mvn clean package -DskipTests
java -jar target\aegis-guard.jar
```

## API Highlights

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `POST /api/v1/auth/register` | none | Create dashboard user |
| `POST /api/v1/auth/login` | none | Get JWT |
| `GET /api/v1/telemetry/stats` | Bearer JWT | Dashboard counters |
| `GET /api/v1/telemetry/agents` | Bearer JWT | Agent inventory |
| `GET /api/v1/telemetry/recent` | Bearer JWT | Recent NodeTrace telemetry |
| `GET /api/v1/rules/` | Bearer JWT | List custom detection rules |
| `POST /api/v1/rules/` | Bearer JWT | Create custom detection rule |
| `POST /register` | enrollment key | NodeTrace compatibility registration |
| `POST /update` | agent Bearer token | NodeTrace telemetry upload |

## Security Notes

This project is safe for local development only until these production tasks are complete:

- Replace every default secret in `.env`.
- For production, use `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` to avoid exposing Postgres/Redis ports.
- Store JWTs in a safer browser session model than long-lived `localStorage` tokens.
- Add incremental Alembic migrations for future schema changes.
- Keep `AEGIS_LOG_LEVEL=INFO` or stricter in production.

Use this software only on systems where you have explicit permission.
