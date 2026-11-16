from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker  # type: ignore[attr-defined]
from sqlalchemy.orm import DeclarativeBase  # type: ignore[attr-defined]
from app.core.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Create all tables — used in dev/test. Production uses Alembic.

    Uvicorn runs more than one worker, and every worker executes the lifespan.
    Without a cross-process lock `create_all(checkfirst=True)` races and one
    worker loses with a duplicate `pg_type` error. A transaction-scoped
    advisory lock serialises bootstrap on Postgres; SQLite is single-writer
    and keeps the simple path used by tests.
    """
    async with engine.begin() as conn:
        if conn.dialect.name == "postgresql":
            await conn.execute(
                text("SELECT pg_advisory_xact_lock(:key)"),
                {"key": 0x4B52414B454E},
            )
        await conn.run_sync(Base.metadata.create_all)
