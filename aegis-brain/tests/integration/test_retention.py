"""Audit F-05: purge sicura e idempotente (serve DB di test)."""
import pytest
from app.services.retention import run_retention_purge


@pytest.mark.asyncio
async def test_purge_twice_is_idempotent(db_session):
    first = await run_retention_purge(db_session, confirmed=True,
                                      backup_verified=True, include_audit=False)
    assert first["dry_run"] is False
    assert "audit" not in first["purged"]
    second = await run_retention_purge(db_session, confirmed=True,
                                       backup_verified=True, include_audit=False)
    assert second["dry_run"] is False
    assert second["purged"] == {k: 0 for k in second["purged"]}


@pytest.mark.asyncio
async def test_purge_never_touches_audit_by_default(db_session):
    from datetime import datetime, timedelta, timezone
    from app.database.models import AuditLog
    from sqlalchemy import select, func
    # Riga audit vecchia di 400 giorni: la purge NON deve cancellarla
    # (la purge stessa ne aggiunge una nuova di log: quella e' attesa).
    old = AuditLog(action="test_probe", resource="test",
                   created_at=datetime.now(timezone.utc) - timedelta(days=400))
    db_session.add(old)
    await db_session.commit()
    rep = await run_retention_purge(db_session, confirmed=True,
                                    backup_verified=True, include_audit=False)
    assert "audit" not in rep["purged"]
    kept = await db_session.execute(
        select(func.count(AuditLog.id)).where(AuditLog.action == "test_probe"))
    assert kept.scalar() == 1
