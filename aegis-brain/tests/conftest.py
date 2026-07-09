import os
import sys

# Ensure test/dev imports succeed before app settings validation runs.
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("JWT_SECRET", "test_jwt_secret_for_testing_only_32_chars_minimum_length")
os.environ.setdefault("AGENT_ENROLL_KEY", "test_enrollment_token_16_chars_min")
os.environ.setdefault("MASTER_KEY_B64", "Q/wCZ5reU82bQpZppUc6Qq80sybBPz4Q276NbMBF97Q=")

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Avoid pytest path shadowing from a stale `app` module cache.
for _mod in ("app", "app.main"):
    sys.modules.pop(_mod, None)

import asyncio
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool

from app.main import app
from app.database.connection import get_db, Base
from app.core.config import settings
from app.database.models import User, Agent
from app.core.security import hash_password, create_access_token
import uuid


# Force test database URL — never use production DB for tests
_env_db = os.getenv("DATABASE_URL", "")
if os.getenv("TEST_DATABASE_URL"):
    TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
elif "aegis" in _env_db and "test" not in _env_db.lower():
    # Rewrite production URL to aegis_test
    parts = _env_db.rsplit("/", 1)
    TEST_DATABASE_URL = parts[0] + "/aegis_test"
else:
    TEST_DATABASE_URL = _env_db or "postgresql+asyncpg://postgres:password@localhost:5432/aegis_test"

TEST_REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Ensure test database exists by connecting to default `postgres` database first
async def _ensure_test_db():
    """Create aegis_test database if it doesn't exist."""
    try:
        root_url = TEST_DATABASE_URL.rsplit("/", 1)[0] + "/postgres"
        engine = create_async_engine(root_url, isolation_level="AUTOCOMMIT", poolclass=NullPool)
        async with engine.begin() as conn:
            from sqlalchemy import text
            db_name = TEST_DATABASE_URL.rsplit("/", 1)[-1]
            result = await conn.execute(text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": db_name})
            if not result.scalar():
                await conn.execute(text(f"CREATE DATABASE \"{db_name}\""))
                print(f"Created test database: {db_name}")
        await engine.dispose()
    except Exception as e:
        print(f"Note: Could not ensure test database exists: {e}")

try:
    asyncio.run(_ensure_test_db())
except Exception:
    pass

_db_available = False
try:
    test_engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool, echo=False)
    TestAsyncSessionLocal = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    _db_available = True
except Exception:
    test_engine = None
    TestAsyncSessionLocal = None


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
async def setup_database():
    if not _db_available:
        yield
        return
    try:
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
        yield
        async with test_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    except Exception:
        yield
    finally:
        if test_engine:
            await test_engine.dispose()


@pytest.fixture
async def db_session():
    if not _db_available:
        pytest.skip("Database not available")
    conn = await test_engine.connect()
    trans = await conn.begin()
    session = TestAsyncSessionLocal(bind=conn)
    yield session
    await session.close()
    await trans.rollback()
    await conn.close()


@pytest.fixture
async def client(db_session):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
async def test_user(db_session):
    user = User(
        username="testuser",
        email="test@example.com",
        password_hash=hash_password("testpass123"),
        role="user",
        active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def admin_user(db_session):
    user = User(
        username="admin",
        email="admin@example.com",
        password_hash=hash_password("adminpass123"),
        role="admin",
        active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def test_agent(db_session):
    agent = Agent(
        agent_id=uuid.uuid4(),
        hostname="test-host",
        os_type="linux",
        agent_type="nodetrace",
        device_token_hash=hash_password("agent-secret"),
    )
    db_session.add(agent)
    await db_session.commit()
    await db_session.refresh(agent)
    return agent


@pytest.fixture
def user_auth_headers(test_user):
    token, _, _ = create_access_token(subject=str(test_user.id), role=test_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_auth_headers(admin_user):
    token, _, _ = create_access_token(subject=str(admin_user.id), role=admin_user.role)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def agent_auth_headers(test_agent):
    return {
        "Authorization": f"Bearer agent-secret",
        "X-Agent-Id": str(test_agent.agent_id)
    }