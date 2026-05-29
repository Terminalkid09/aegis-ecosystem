import os
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
import pytest
from unittest.mock import AsyncMock, MagicMock

# Imposta le variabili d'ambiente per i test PRIMA di importare il resto
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["AEGIS_API_KEY"] = "test-secret-key"
os.environ["MASTER_KEY_B64"] = "Q/wCZ5reU82bQpZppUc6Qq80sybBPz4Q276NbMBF97Q="
os.environ["JWT_SECRET"] = "test-jwt-secret"
os.environ["OLLAMA_URL"] = "http://localhost:11434/api/generate"
os.environ["REDIS_URL"] = "redis://localhost:6379"

# Mock Redis before importing app modules that use it
import redis.asyncio as redis
mock_redis = MagicMock()
mock_redis.exists = AsyncMock(return_value=False)
mock_redis.get = AsyncMock(return_value=None)
mock_redis.set = AsyncMock(return_value=True)
mock_redis.setex = AsyncMock(return_value=True)
mock_redis.incr = AsyncMock(return_value=1)
mock_redis.expire = AsyncMock(return_value=True)

redis.from_url = MagicMock(return_value=mock_redis)
redis.Redis = MagicMock(return_value=mock_redis)

from app.database.base import Base
import app.database.connection as dbc

# Test engine e session factory
engine = create_async_engine(os.environ["DATABASE_URL"], echo=False)
TestingSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

# Patch del modulo di connessione dell'app
dbc.engine = engine
dbc.AsyncSessionLocal = TestingSessionLocal

@pytest.fixture(scope="session", autouse=True)
async def setup_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()

@pytest.fixture
async def db_session():
    async with TestingSessionLocal() as session:
        yield session

@pytest.fixture
def mock_redis_client():
    return mock_redis
