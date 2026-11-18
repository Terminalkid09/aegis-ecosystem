from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

from loguru import logger
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


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
# Before Alembic was wired into startup, the service created its schema with
# `Base.metadata.create_all`. Such databases have no `alembic_version` row but
# do contain the 0001-0003 tables. 0003 is the last create_all-era revision.
_LEGACY_BASELINE = "0003"


def _legacy_baseline(
    *,
    has_version_table: bool,
    has_legacy_schema: bool,
    has_new_tables: bool,
    has_ntlm_hash: bool,
) -> str | None:
    """Return the revision to stamp before upgrading, or None.

    A fresh database upgrades from base normally. A legacy create_all database
    is stamped at 0003, then 0004-0006 run. A database where a 4.2 candidate
    already created the new tables but has no version row is stamped at the
    current head only when its schema is demonstrably complete; a partial
    upgrade is refused instead of being silently accepted.
    """
    if has_version_table or not has_legacy_schema:
        return None
    if has_new_tables:
        if has_ntlm_hash:
            return "0006"
        raise RuntimeError(
            "Kraken schema has 4.2 tables but no alembic_version and no "
            "credential_attempts.ntlm_hash; refusing an ambiguous upgrade"
        )
    return _LEGACY_BASELINE


def _alembic_command() -> str:
    """Resolve the Alembic CLI without importing the shadowed local package.

    `services/kraken/alembic/` is the migration directory. When the app is
    started from the service root, a normal `import alembic` resolves to that
    directory instead of the installed distribution, so the migration runner
    must stay out of process. The console script next to the interpreter is
    the same one used by the container image.
    """
    sibling = Path(sys.executable).with_name("alembic.exe" if os.name == "nt" else "alembic")
    if sibling.exists():
        return str(sibling)
    return shutil.which("alembic") or "alembic"


def _run_alembic(action: str, revision: str) -> None:
    """Run Alembic in this worker thread (its env.py creates its own loop)."""
    if action not in {"stamp", "upgrade"}:
        raise ValueError(f"unsupported Alembic action: {action}")
    command = [_alembic_command(), action, revision]
    logger.info("Running Kraken migration command: {}", " ".join(command[1:]))
    result = subprocess.run(
        command,
        cwd=_PROJECT_ROOT,
        env={**os.environ, "DATABASE_URL": settings.DATABASE_URL},
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"alembic {action} {revision} failed: {detail[-2000:]}")


async def _postgres_schema_state(conn) -> tuple[bool, bool, bool, bool]:
    version_table = (
        await conn.execute(text("SELECT to_regclass('public.alembic_version')"))
    ).scalar()
    legacy_schema = (
        await conn.execute(text("SELECT to_regclass('public.attack_events')"))
    ).scalar()
    campaigns = (
        await conn.execute(text("SELECT to_regclass('public.campaigns')"))
    ).scalar()
    analysis_jobs = (
        await conn.execute(text("SELECT to_regclass('public.analysis_jobs')"))
    ).scalar()
    ntlm_hash = (
        await conn.execute(
            text(
                "SELECT 1 FROM information_schema.columns "
                "WHERE table_schema = 'public' AND table_name = 'credential_attempts' "
                "AND column_name = 'ntlm_hash'"
            )
        )
    ).scalar()
    return (
        version_table is not None,
        legacy_schema is not None,
        campaigns is not None and analysis_jobs is not None,
        ntlm_hash is not None,
    )


async def init_db():
    """Bring the database to the Alembic head before serving requests.

    SQLite remains the create_all path used by unit tests and local scripts.
    PostgreSQL is always migrated: a fresh database starts from base, while a
    legacy database created by the old create_all bootstrap is stamped at 0003
    first. The two uvicorn workers exit if the migration fails, so the service
    never runs against a partially upgraded schema.
    """
    if engine.dialect.name != "postgresql":
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        return

    lock_conn = await engine.connect()
    try:
        # Hold a session-level lock while Alembic runs, so the two uvicorn
        # workers cannot both apply the same revision. The lock is released
        # explicitly in `finally` (and by PostgreSQL if the process dies).
        await lock_conn.execute(
            text("SELECT pg_advisory_lock(:key)"),
            {"key": 0x4B52414B454E},
        )
        await lock_conn.commit()
        state = await _postgres_schema_state(lock_conn)
        await lock_conn.commit()
        baseline = _legacy_baseline(
            has_version_table=state[0],
            has_legacy_schema=state[1],
            has_new_tables=state[2],
            has_ntlm_hash=state[3],
        )
        if baseline:
            logger.info("Kraken legacy schema detected; stamping Alembic {}", baseline)
            await asyncio.to_thread(_run_alembic, "stamp", baseline)
        await asyncio.to_thread(_run_alembic, "upgrade", "head")
        logger.info("Kraken database migrations applied")
    except Exception as exc:
        logger.error("Kraken database migration failed: {}", exc)
        raise
    finally:
        try:
            await lock_conn.execute(
                text("SELECT pg_advisory_unlock(:key)"),
                {"key": 0x4B52414B454E},
            )
            await lock_conn.commit()
        finally:
            await lock_conn.close()
