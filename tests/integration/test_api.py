import pytest
import pytest_asyncio
import tempfile
import os
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.main import app
from app.db.session import get_db, Base
from app.models.models import User
from app.core.security import hash_password
from app.core.config import settings

INTERNAL_KEY = settings.INTERNAL_API_KEY

_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
TEST_DB_URL = f"sqlite+aiosqlite:///{_tmp_db.name}"
engine = create_async_engine(TEST_DB_URL, echo=False)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def auth(token): return {"Authorization": f"Bearer {token}"}
def ikey(): return {"X-Internal-API-Key": INTERNAL_KEY}


async def _override_db():
    async with SessionLocal() as s:
        yield s


@pytest_asyncio.fixture(scope="module", autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
    try:
        os.unlink(_tmp_db.name)
    except OSError:
        pass


@pytest_asyncio.fixture
async def client():
    app.dependency_overrides[get_db] = _override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def auth_token(client):
    import uuid
    uname = f"admin-{uuid.uuid4().hex[:8]}"
    async with SessionLocal() as db:
        db.add(User(username=uname, hashed_password=hash_password("adminpass"),
                    is_admin=True, is_active=True))
        await db.commit()
    res = await client.post("/api/v1/auth/login", json={"username": uname, "password": "adminpass"})
    return res.json()["access_token"]


# ── Health ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health(client):
    res = await client.get("/api/v1/health")
    assert res.status_code == 200 and res.json()["status"] == "ok"


# ── Auth ──────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_success(client):
    import uuid
    uname = f"u1-{uuid.uuid4().hex[:8]}"
    async with SessionLocal() as db:
        db.add(User(username=uname, hashed_password=hash_password("pass1"), is_active=True))
        await db.commit()
    res = await client.post("/api/v1/auth/login", json={"username": uname, "password": "pass1"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_failure(client):
    res = await client.post("/api/v1/auth/login", json={"username": "nobody", "password": "wrong"})
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_register_duplicate(client, monkeypatch):
    import uuid
    monkeypatch.setattr(settings, "ALLOW_REGISTRATION", True)
    uname = f"dup-{uuid.uuid4().hex[:8]}"
    async with SessionLocal() as db:
        db.add(User(username=uname, hashed_password=hash_password("pass1"), is_active=True))
        await db.commit()
    res = await client.post("/api/v1/auth/register", json={"username": uname, "password": "pass1234"})
    assert res.status_code == 400
    assert "already taken" in res.json()["detail"]


# ── Events ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ingest_no_key(client):
    res = await client.post("/api/v1/events/ingest", json={
        "sensor_type": "ssh", "attacker_ip": "5.6.7.8",
        "attacker_port": 55000, "sensor_port": 2222, "session_id": "ingest-002",
    })
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_ingest_success(client):
    with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
        res = await client.post("/api/v1/events/ingest", headers=ikey(), json={
            "sensor_type": "ssh", "attacker_ip": "5.6.7.8",
            "attacker_port": 55000, "sensor_port": 2222, "session_id": "ingest-001",
            "username": "root", "password": "root",
        })
    assert res.status_code == 201
    data = res.json()
    assert data["session_id"] == "ingest-001"
    assert data["sensor_type"] == "ssh"


@pytest.mark.asyncio
async def test_ingest_with_commands(client):
    with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
        res = await client.post("/api/v1/events/ingest", headers=ikey(), json={
            "sensor_type": "telnet", "attacker_ip": "10.0.0.99",
            "attacker_port": 44000, "sensor_port": 2323, "session_id": "ingest-003",
            "commands": ["id", "whoami", "cat /etc/passwd"],
        })
    assert res.status_code == 201
    assert res.json()["session_id"] == "ingest-003"


@pytest.mark.asyncio
async def test_ingest_invalid_sensor(client):
    res = await client.post("/api/v1/events/ingest", headers=ikey(), json={
        "sensor_type": "unknown", "attacker_ip": "5.6.7.8",
        "attacker_port": 55000, "sensor_port": 2222, "session_id": "ingest-004",
    })
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_list_events_authenticated(client, auth_token):
    with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
        await client.post("/api/v1/events/ingest", headers=ikey(), json={
            "sensor_type": "ssh", "attacker_ip": "1.2.3.4",
            "attacker_port": 12345, "sensor_port": 2222, "session_id": "list-001",
        })
        await client.post("/api/v1/events/ingest", headers=ikey(), json={
            "sensor_type": "ftp", "attacker_ip": "5.6.7.8",
            "attacker_port": 54321, "sensor_port": 2121, "session_id": "list-002",
        })
    res = await client.get("/api/v1/events/", headers=auth(auth_token))
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) >= 2


@pytest.mark.asyncio
async def test_list_events_sensor_filter(client, auth_token):
    with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
        await client.post("/api/v1/events/ingest", headers=ikey(), json={
            "sensor_type": "ssh", "attacker_ip": "1.2.3.5",
            "attacker_port": 12345, "sensor_port": 2222, "session_id": "flt-001",
        })
    res = await client.get("/api/v1/events/?sensor_type=ssh", headers=auth(auth_token))
    assert res.status_code == 200
    data = res.json()
    assert all(e["sensor_type"] == "ssh" for e in data)


@pytest.mark.asyncio
async def test_dashboard_stats(client, auth_token):
    res = await client.get("/api/v1/events/stats", headers=auth(auth_token))
    assert res.status_code == 200
    data = res.json()
    for key in ("total_attacks", "attacks_today", "unique_ips", "top_countries", "top_sensors", "attacks_over_time", "geo_points"):
        assert key in data
