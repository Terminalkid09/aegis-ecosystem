"""Retention degli eventi SIEM collegata al job di retention.

Perché esiste questo test: `siem_store.purge_expired` era implementato ma non
veniva chiamato da nessuno, quindi gli eventi normalizzati si accumulavano
senza limite mentre il resto delle tabelle veniva purgato. Era un difetto
invisibile — nessun errore, solo crescita continua del database — ed è il
motivo per cui il percorso di retention va verificato e non dedotto.

Verifica che:
1. il preview includa `siem_events` (altrimenti l'operatore vedrebbe "0" e
   non capirebbe perché il DB cresce);
2. la purge elimini davvero gli eventi oltre la retention.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from app.core.config import settings
from app.database.connection import AsyncSessionLocal
from app.database.models import SiemEvent
from app.services import siem_store
from app.services.retention import preview_retention


def _old_time(days: int = 7) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days)


async def _insert_event(source: str, event_id: str, when: datetime) -> None:
    async with AsyncSessionLocal() as db:
        event = SiemEvent(
            time=when, source=source, source_type="syslog", event_id=event_id,
            severity="INFO", message=f"retention probe {event_id}",
        )
        db.add(event)
        await db.commit()


async def _count(source: str) -> int:
    async with AsyncSessionLocal() as db:
        return int(await db.scalar(
            select(func.count(SiemEvent.id)).where(SiemEvent.source == source)) or 0)


async def test_expired_siem_event_is_removed_by_retention():
    # Evento più vecchio della retention configurata: deve sparire.
    source = f"retention-old-{datetime.now(timezone.utc).timestamp():.0f}"
    await _insert_event(source, f"old-{source}", _old_time(settings.SIEM_RETENTION_DAYS + 5))
    assert await _count(source) == 1

    async with AsyncSessionLocal() as db:
        result = await siem_store.purge_expired(db, settings.SIEM_RETENTION_DAYS)
        await db.commit()

    assert await _count(source) == 0, "l'evento scaduto non è stato purgato"
    assert result["retention_days"] == settings.SIEM_RETENTION_DAYS


async def test_recent_siem_event_survives_retention():
    source = f"retention-new-{datetime.now(timezone.utc).timestamp():.0f}"
    await _insert_event(source, f"new-{source}", _old_time(1))
    async with AsyncSessionLocal() as db:
        await siem_store.purge_expired(db, settings.SIEM_RETENTION_DAYS)
        await db.commit()
    assert await _count(source) == 1, "la retention ha cancellato un evento recente"


async def test_preview_retention_reports_siem_events():
    """Il preview deve dire la verità anche sul SIEM."""
    source = f"retention-preview-{datetime.now(timezone.utc).timestamp():.0f}"
    await _insert_event(source, f"preview-{source}",
                        _old_time(settings.SIEM_RETENTION_DAYS + 3))
    async with AsyncSessionLocal() as db:
        preview = await preview_retention(db)
    assert "siem_events" in preview["counts"], \
        "il preview non considera gli eventi SIEM: l'operatore vedrebbe 0"
    assert "siem_events" in preview["cutoffs"]
    assert preview["counts"]["siem_events"] >= 1
