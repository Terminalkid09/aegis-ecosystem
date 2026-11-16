"""Worker della outbox transazionale Kraken → Aegis.

Il worker non condivide transazioni con l'ingest: prende in carico una riga con
un UPDATE condizionale (così due processi non la spediscono entrambi), invia
fuori transazione e poi registra l'esito. Un crash tra invio e aggiornamento
lascia la riga in `processing`; dopo `AEGIS_OUTBOX_STALE_AFTER_S` viene
recuperata e rispedita. Il Brain deduplica per `event_id`, quindi il replay è
sicuro.
"""
from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta

from loguru import logger
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.core.metrics import (
    record_outbox_attempt,
    record_outbox_failed,
    record_outbox_sent,
    set_outbox_pending,
)
from app.db.session import AsyncSessionLocal
from app.models.models import Outbox
from app.services.aegis_ingest import DeliveryResult, send_payload

SessionFactory = async_sessionmaker[AsyncSession]
Sender = Callable[[dict], Awaitable[DeliveryResult]]

_worker_task: asyncio.Task | None = None
_stop_event: asyncio.Event | None = None


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _backoff_seconds(attempts: int) -> float:
    base = max(0.1, settings.AEGIS_OUTBOX_BACKOFF_BASE_S)
    cap = max(base, settings.AEGIS_OUTBOX_BACKOFF_MAX_S)
    exponential = base * (2 ** max(0, attempts - 1))
    # Jitter 0.5–1.5x: evita che più righe ripartano nello stesso istante.
    return min(cap, exponential) * (0.5 + random.random())


async def _recover_stale(session_factory: SessionFactory, now: datetime) -> int:
    cutoff = now - timedelta(seconds=max(1, settings.AEGIS_OUTBOX_STALE_AFTER_S))
    async with session_factory() as session:
        result = await session.execute(
            update(Outbox)
            .where(
                Outbox.status == "processing",
                Outbox.claimed_at.is_not(None),
                Outbox.claimed_at < cutoff,
            )
            .values(
                status="pending",
                claimed_at=None,
                next_attempt_at=now,
                last_error="worker stale; requeued",
            )
        )
        await session.commit()
    recovered = result.rowcount or 0
    if recovered:
        logger.warning(f"Outbox: recovered {recovered} stale processing row(s)")
    return recovered


async def _claim(session_factory: SessionFactory, outbox_id: int, now: datetime) -> bool:
    """Atomically move one due row from pending to processing.

    The conditional UPDATE is the lock: with two workers only one gets
    `rowcount == 1`, without relying on PostgreSQL-only SKIP LOCKED.
    """
    async with session_factory() as session:
        result = await session.execute(
            update(Outbox)
            .where(
                Outbox.id == outbox_id,
                Outbox.status == "pending",
                Outbox.next_attempt_at <= now,
            )
            .values(status="processing", claimed_at=now)
        )
        await session.commit()
    return (result.rowcount or 0) == 1


async def _load(session_factory: SessionFactory, outbox_id: int) -> dict | None:
    async with session_factory() as session:
        row = await session.get(Outbox, outbox_id)
        if row is None:
            return None
        return {
            "id": row.id,
            "event_id": row.event_id,
            "payload": row.payload,
            "attempts": row.attempts,
        }


async def _mark_sent(session_factory: SessionFactory, outbox_id: int, now: datetime) -> None:
    async with session_factory() as session:
        await session.execute(
            update(Outbox)
            .where(Outbox.id == outbox_id)
            .values(
                status="sent",
                attempts=Outbox.attempts + 1,
                sent_at=now,
                claimed_at=None,
                last_error=None,
            )
        )
        await session.commit()


async def _mark_failure(
    session_factory: SessionFactory,
    outbox_id: int,
    attempts: int,
    result: DeliveryResult,
    now: datetime,
) -> str:
    new_attempts = attempts + 1
    max_attempts = max(1, settings.AEGIS_OUTBOX_MAX_ATTEMPTS)
    retry = result.retryable and new_attempts < max_attempts

    values = {
        "attempts": new_attempts,
        "claimed_at": None,
        "last_error": (result.error or "delivery failed")[:2000],
    }
    if retry:
        values["status"] = "pending"
        values["next_attempt_at"] = now + timedelta(seconds=_backoff_seconds(new_attempts))
    else:
        values["status"] = "failed"

    async with session_factory() as session:
        await session.execute(
            update(Outbox).where(Outbox.id == outbox_id).values(**values)
        )
        await session.commit()

    reason = "max_attempts" if result.retryable else "poison"
    if not retry:
        record_outbox_failed(reason)
    return "retried" if retry else "failed"


async def _refresh_pending(session_factory: SessionFactory) -> int:
    async with session_factory() as session:
        pending = await session.scalar(
            select(func.count(Outbox.id)).where(Outbox.status == "pending")
        )
    pending = int(pending or 0)
    set_outbox_pending(pending)
    return pending


async def process_outbox_once(
    session_factory: SessionFactory = AsyncSessionLocal,
    sender: Sender = send_payload,
    *,
    now: datetime | None = None,
    batch_size: int | None = None,
) -> dict:
    """Drain one due batch. Returns counters useful in tests and logs."""
    now = now or _utcnow()
    limit = max(1, batch_size or settings.AEGIS_OUTBOX_BATCH_SIZE)
    summary = {"claimed": 0, "sent": 0, "retried": 0, "failed": 0}

    await _recover_stale(session_factory, now)

    async with session_factory() as session:
        ids = list((await session.execute(
            select(Outbox.id)
            .where(Outbox.status == "pending", Outbox.next_attempt_at <= now)
            .order_by(Outbox.next_attempt_at, Outbox.id)
            .limit(limit)
        )).scalars().all())

    for outbox_id in ids:
        if not await _claim(session_factory, outbox_id, now):
            continue
        summary["claimed"] += 1

        row = await _load(session_factory, outbox_id)
        if row is None:
            continue

        try:
            result = await sender(row["payload"])
        except Exception as exc:  # noqa: BLE001 - sender boundary must not kill the worker
            logger.warning(f"Outbox sender raised: {type(exc).__name__}")
            result = DeliveryResult(False, True, error=type(exc).__name__)

        if result.ok:
            await _mark_sent(session_factory, outbox_id, now)
            record_outbox_sent()
            record_outbox_attempt("success")
            summary["sent"] += 1
            continue

        outcome = await _mark_failure(
            session_factory, outbox_id, row["attempts"], result, now
        )
        record_outbox_attempt("retryable" if result.retryable else "poison")
        summary[outcome] += 1
        logger.warning(
            f"Outbox event {row['event_id']} not delivered: "
            f"{result.error or result.status_code} ({outcome})"
        )

    await _refresh_pending(session_factory)
    return summary


async def _run_worker(stop_event: asyncio.Event) -> None:
    logger.info("Outbox worker started")
    while True:
        try:
            await process_outbox_once()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - one bad cycle must not stop the worker
            logger.exception("Outbox worker cycle failed")

        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=max(0.1, settings.AEGIS_OUTBOX_POLL_INTERVAL_S),
            )
        except TimeoutError:
            pass


def start_outbox_worker() -> None:
    global _worker_task, _stop_event
    if not settings.AEGIS_INGEST_ENABLED:
        logger.info("Outbox worker disabled: AEGIS_INGEST_ENABLED=false")
        return
    if _worker_task is not None and not _worker_task.done():
        return
    _stop_event = asyncio.Event()
    _worker_task = asyncio.create_task(_run_worker(_stop_event), name="kraken-outbox")


async def stop_outbox_worker() -> None:
    global _worker_task, _stop_event
    task = _worker_task
    if task is None:
        return
    if _stop_event is not None:
        _stop_event.set()
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task
    _worker_task = None
    _stop_event = None
    logger.info("Outbox worker stopped")
