import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import app
from app.db.session import get_db, Base
from app.core.config import settings
from app.models.models import User
from app.core.security import hash_password, create_access_token

import tempfile

_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)

# Use file-based SQLite so all connections share the same database
TEST_DATABASE_URL = f"sqlite+aiosqlite:///{_tmp_db.name}"

test_engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool, echo=False)
TestAsyncSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
async def setup_database():
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await test_engine.dispose()
    try:
        os.unlink(_tmp_db.name)
    except OSError:
        pass


@pytest.fixture
async def db_session():
    async with TestAsyncSessionLocal() as session:
        yield session
        await session.rollback()


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
    import uuid
    user = User(
        username=f"testuser-{uuid.uuid4().hex[:8]}",
        hashed_password=hash_password("testpass123"),
        is_admin=False,
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def admin_user(db_session):
    import uuid
    user = User(
        username=f"admin-{uuid.uuid4().hex[:8]}",
        hashed_password=hash_password("adminpass123"),
        is_admin=True,
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.refresh(user)
    return user


@pytest.fixture
def auth_headers(test_user):
    token = create_access_token(subject=test_user.username)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_auth_headers(admin_user):
    token = create_access_token(subject=admin_user.username)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
async def setup_redis():
    """Mock Redis for tests — no real Redis needed."""
    class FakeRedis:
        async def ping(self):
            return True
        async def get(self, key):
            return None
        async def set(self, key, val, ex=None):
            pass
        async def exists(self, key):
            return 0
        async def info(self, section=None):
            return {"used_memory_human": "1M"}
        async def aclose(self):
            pass

    settings.REDIS_URL = "redis://localhost:6379/0"
    settings.REDIS_PASSWORD = None
    # Override redis_client with fake
    import app.db.redis as rmod
    rmod.redis_client = FakeRedis()
    yield
    rmod.redis_client = None
