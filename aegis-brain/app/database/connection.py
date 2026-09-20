from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
from app.core.config import settings
from app.database.base import Base
from app.database import models  # noqa: F401 - register SQLAlchemy models in Base.metadata

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")

_engine_kwargs: dict = {"echo": settings.DEBUG, "future": True}
if _is_sqlite:
    # SQLite (aiosqlite) does not support pool_size/max_overflow/pool_timeout.
    # Use NullPool so imports work in tests/dev without Postgres.
    _engine_kwargs["poolclass"] = NullPool
    _engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    _engine_kwargs.update(
        pool_size=30,
        max_overflow=50,
        pool_pre_ping=True,
        pool_timeout=60,
        pool_recycle=300,
    )

engine = create_async_engine(settings.DATABASE_URL, **_engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

async def init_db():
    if settings.DB_BOOTSTRAP_CREATE_ALL:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
