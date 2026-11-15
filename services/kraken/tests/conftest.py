import pytest
import asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
import os
import sys
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The monorepo has no service-local .env (and never should): use fixed,
# non-production test secrets so importing the app cannot fail on an empty key.
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("SECRET_KEY", "test-kraken-secret-key-32-characters-minimum")
os.environ.setdefault("INTERNAL_API_KEY", "test-kraken-internal-key-32-characters-minimum")

# KRAKEN-LOGIC-005: never write test artefacts into the image's /app.
_TEST_DATA_ROOT = tempfile.mkdtemp(prefix="kraken-test-data-")
os.environ["DATA_DIR"] = _TEST_DATA_ROOT
os.environ["MALWARE_DIR"] = os.path.join(_TEST_DATA_ROOT, "malware")
os.environ["LOGS_DIR"] = os.path.join(_TEST_DATA_ROOT, "logs")
os.environ["SIEM_LOG_FILE"] = os.path.join(_TEST_DATA_ROOT, "logs", "siem.jsonl")

from app.main import app
from app.db.session import get_db, Base
from app.core.config import settings
from app.models.models import User
from app.core.security import hash_password, create_access_token

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
    shutil.rmtree(_TEST_DATA_ROOT, ignore_errors=True)


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
def reset_rate_limiter():
    """Keep the per-IP limiter from leaking between test modules."""
    from app.core.limiter import limiter
    try:
        limiter.reset()
    except Exception:
        pass
    yield


@pytest.fixture(autouse=True)
async def setup_redis():
    """Mock Redis for tests — no real Redis needed."""
    class FakeRedis:
        def __init__(self):
            self.data = {}
        async def ping(self):
            return True
        async def get(self, key):
            return self.data.get(key)
        async def set(self, key, val, ex=None, nx=False):
            if nx and key in self.data:
                return None
            self.data[key] = val
            return True
        async def exists(self, key):
            return 1 if key in self.data else 0
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
