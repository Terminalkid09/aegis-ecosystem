import pytest
import pytest_asyncio
import tempfile
import os
from unittest.mock import AsyncMock, patch
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.db.session import Base
from app.schemas.schemas import SensorEventIn
from app.services.attack_service import ingest_sensor_event, get_events, get_dashboard_stats
from app.services.geoip import GeoIPService

_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
TEST_DB = f"sqlite+aiosqlite:///{_tmp_db.name}"
engine = create_async_engine(TEST_DB, echo=False)
Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


@pytest_asyncio.fixture(autouse=True)
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
async def db():
    async with Session() as s:
        yield s


# ── GeoIP ─────────────────────────────────────────────────────────────────────

def test_geoip_private_ipv4():
    assert GeoIPService().lookup("192.168.1.1")["country"] == "Private Network"

def test_geoip_loopback():
    assert GeoIPService().lookup("127.0.0.1")["country"] == "Private Network"

def test_geoip_private_10():
    assert GeoIPService().lookup("10.0.0.1")["country"] == "Private Network"

def test_geoip_missing_db_returns_dict():
    result = GeoIPService().lookup("8.8.8.8")
    assert isinstance(result, dict) and "country" in result


# ── Schema validation ─────────────────────────────────────────────────────────

def test_schema_rejects_invalid_sensor():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        SensorEventIn(
            sensor_type="invalid_sensor",
            attacker_ip="1.2.3.4", attacker_port=1234,
            sensor_port=2222, session_id="abc-def-123",
        )

def test_schema_rejects_invalid_ip():
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        SensorEventIn(
            sensor_type="ssh", attacker_ip="not_an_ip",
            attacker_port=1234, sensor_port=2222, session_id="abc-def-123",
        )

def test_schema_truncates_commands():
    payload = SensorEventIn(
        sensor_type="http", attacker_ip="1.2.3.4",
        attacker_port=80, sensor_port=8080, session_id="abc-def-456",
        commands=["A" * 1000],
    )
    assert len(payload.commands[0]) == 512


def test_schema_caps_command_count():
    payload = SensorEventIn(
        sensor_type="http", attacker_ip="1.2.3.4",
        attacker_port=80, sensor_port=8080, session_id="abc-def-457",
        commands=["x"] * 250,
    )
    assert len(payload.commands) == 200

def test_schema_normalises_sensor_case():
    payload = SensorEventIn(
        sensor_type="SSH", attacker_ip="1.2.3.4",
        attacker_port=22, sensor_port=2222, session_id="abc-def-789",
    )
    assert payload.sensor_type == "ssh"


# ── Ingest ────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ingest_basic(db):
    p = SensorEventIn(
        sensor_type="ssh", attacker_ip="10.0.0.1",
        attacker_port=54321, sensor_port=2222, session_id="test-001",
        username="root", password="toor",
    )
    with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
        event = await ingest_sensor_event(db, p)
    assert event.id and event.session_id == "test-001" and event.sensor_type == "ssh"

@pytest.mark.asyncio
async def test_ingest_stores_credentials(db):
    p = SensorEventIn(
        sensor_type="ftp", attacker_ip="10.0.0.2",
        attacker_port=2020, sensor_port=2121, session_id="test-002",
        username="admin", password="admin123",
    )
    with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
        event = await ingest_sensor_event(db, p)
    assert len(event.credentials) == 1
    assert event.credentials[0].username == "admin"
    assert event.credentials[0].password.startswith("hmac-sha256:")
    assert "admin123" not in event.credentials[0].password

@pytest.mark.asyncio
async def test_ingest_stores_commands(db):
    p = SensorEventIn(
        sensor_type="http", attacker_ip="10.0.0.3",
        attacker_port=80, sensor_port=8080, session_id="test-003",
        commands=["GET /admin", "GET /.env"],
    )
    with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
        event = await ingest_sensor_event(db, p)
    assert len(event.commands) == 2

@pytest.mark.asyncio
async def test_ingest_duplicate_session_is_idempotent(db):
    p = SensorEventIn(
        sensor_type="ssh", attacker_ip="10.0.0.4",
        attacker_port=1111, sensor_port=2222, session_id="test-dup",
    )
    with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
        first = await ingest_sensor_event(db, p)
        second = await ingest_sensor_event(db, p)
    assert second.id == first.id
    assert len(await get_events(db)) == 1

# ── get_events ────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_events_empty(db):
    assert await get_events(db) == []

@pytest.mark.asyncio
async def test_get_events_filter_sensor(db):
    for i, sensor in enumerate(["ssh", "http", "ftp"]):
        p = SensorEventIn(
            sensor_type=sensor, attacker_ip=f"10.1.0.{i}",
            attacker_port=1000 + i, sensor_port=2000 + i,
            session_id=f"filter-{i}",
        )
        with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
            await ingest_sensor_event(db, p)
    ssh_events = await get_events(db, sensor_type="ssh")
    assert all(e.sensor_type == "ssh" for e in ssh_events)
    assert len(ssh_events) == 1

@pytest.mark.asyncio
async def test_get_events_pagination(db):
    for i in range(10):
        p = SensorEventIn(
            sensor_type="telnet", attacker_ip=f"10.2.0.{i}",
            attacker_port=5000 + i, sensor_port=2323, session_id=f"pagination-{i:03d}",
        )
        with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
            await ingest_sensor_event(db, p)
    page1 = await get_events(db, skip=0, limit=5)
    page2 = await get_events(db, skip=5, limit=5)
    assert len(page1) == 5 and len(page2) == 5
    assert {e.id for e in page1}.isdisjoint({e.id for e in page2})

# ── Stats ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stats_empty(db):
    s = await get_dashboard_stats(db)
    assert s["total_attacks"] == 0 and s["unique_ips"] == 0

@pytest.mark.asyncio
async def test_stats_counts(db):
    for i in range(3):
        p = SensorEventIn(
            sensor_type="ssh", attacker_ip=f"10.3.0.{i}",
            attacker_port=6000 + i, sensor_port=2222, session_id=f"stats-count-{i}",
        )
        with patch("app.services.attack_service.telegram_service.send_alert", new_callable=AsyncMock):
            await ingest_sensor_event(db, p)
    s = await get_dashboard_stats(db)
    assert s["total_attacks"] == 3 and s["unique_ips"] == 3
