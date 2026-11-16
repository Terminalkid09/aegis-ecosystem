import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import delete, func, select

from app.core.config import settings
from app.models.models import Outbox
from app.schemas.schemas import SensorEventIn
from app.services.aegis_ingest import DeliveryResult
from app.services.attack_service import ingest_sensor_event
from app.services.outbox import process_outbox_once


@pytest.fixture(autouse=True)
async def clean_outbox(db_session):
    """The test DB is session-scoped; do not let one test drain another's rows."""
    await db_session.execute(delete(Outbox))
    await db_session.commit()
    yield
    await db_session.execute(delete(Outbox))
    await db_session.commit()


def _sensor_payload(session_id: str, *, password: str = "must-not-leave") -> SensorEventIn:
    return SensorEventIn(
        sensor_type="ssh",
        attacker_ip="45.9.20.7",
        attacker_port=51244,
        sensor_port=22,
        session_id=session_id,
        username="root",
        password=password,
        commands=["uname -a"],
    )


def _due_row(session_id: str, *, now: datetime) -> Outbox:
    return Outbox(
        event_id=f"kraken:ssh:{session_id}:0",
        payload={"events": [{"event_id": f"kraken:ssh:{session_id}:0"}]},
        status="pending",
        attempts=0,
        next_attempt_at=now - timedelta(seconds=1),
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


@pytest.mark.asyncio
async def test_ingest_writes_event_and_outbox_together(db_session, monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_INGEST_ENABLED", True)
    session_id = f"outbox-{uuid.uuid4().hex[:12]}"

    event = await ingest_sensor_event(db_session, _sensor_payload(session_id))

    row = (await db_session.execute(
        select(Outbox).where(Outbox.event_id == f"kraken:ssh:{session_id}:0")
    )).scalar_one()
    assert event.session_id == session_id
    assert row.status == "pending"
    assert row.attempts == 0
    assert row.payload["events"][0]["network"]["src_ip"] == "45.9.20.7"
    assert row.payload["events"][0]["process"]["command_line"] == "uname -a"
    assert "must-not-leave" not in json.dumps(row.payload)


@pytest.mark.asyncio
async def test_duplicate_ingest_does_not_enqueue_twice(db_session, monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_INGEST_ENABLED", True)
    session_id = f"outbox-{uuid.uuid4().hex[:12]}"
    payload = _sensor_payload(session_id)

    await ingest_sensor_event(db_session, payload)
    await ingest_sensor_event(db_session, payload)

    count = await db_session.scalar(
        select(func.count(Outbox.id)).where(
            Outbox.event_id == f"kraken:ssh:{session_id}:0"
        )
    )
    assert count == 1


@pytest.mark.asyncio
async def test_outbox_retries_5xx_with_backoff(db_session, test_session_factory, monkeypatch):
    now = datetime.now(UTC)
    session_id = f"retry-{uuid.uuid4().hex[:12]}"
    row = _due_row(session_id, now=now)
    db_session.add(row)
    await db_session.commit()

    calls = []

    async def sender(payload):
        calls.append(payload)
        return DeliveryResult(False, True, status_code=503, error="brain down")

    summary = await process_outbox_once(
        test_session_factory, sender, now=now, batch_size=10
    )

    await db_session.refresh(row)
    assert summary["retried"] == 1
    assert len(calls) == 1
    assert row.status == "pending"
    assert row.attempts == 1
    assert _aware(row.next_attempt_at) > now
    assert "brain down" in (row.last_error or "")


@pytest.mark.asyncio
async def test_outbox_poison_4xx_is_not_retried(db_session, test_session_factory):
    now = datetime.now(UTC)
    session_id = f"poison-{uuid.uuid4().hex[:12]}"
    row = _due_row(session_id, now=now)
    db_session.add(row)
    await db_session.commit()

    async def sender(payload):
        return DeliveryResult(False, False, status_code=422, error="invalid event")

    summary = await process_outbox_once(
        test_session_factory, sender, now=now, batch_size=10
    )

    await db_session.refresh(row)
    assert summary["failed"] == 1
    assert row.status == "failed"
    assert row.attempts == 1
    assert "invalid event" in (row.last_error or "")


@pytest.mark.asyncio
async def test_outbox_success_marks_sent(db_session, test_session_factory):
    now = datetime.now(UTC)
    session_id = f"sent-{uuid.uuid4().hex[:12]}"
    row = _due_row(session_id, now=now)
    db_session.add(row)
    await db_session.commit()

    async def sender(payload):
        return DeliveryResult(True, False, status_code=200)

    summary = await process_outbox_once(
        test_session_factory, sender, now=now, batch_size=10
    )

    await db_session.refresh(row)
    assert summary["sent"] == 1
    assert row.status == "sent"
    assert row.attempts == 1
    assert row.sent_at is not None
    assert row.claimed_at is None


@pytest.mark.asyncio
async def test_outbox_recovers_stale_processing_row(db_session, test_session_factory):
    now = datetime.now(UTC)
    session_id = f"stale-{uuid.uuid4().hex[:12]}"
    row = _due_row(session_id, now=now)
    row.status = "processing"
    row.claimed_at = now - timedelta(
        seconds=settings.AEGIS_OUTBOX_STALE_AFTER_S + 5
    )
    db_session.add(row)
    await db_session.commit()

    async def sender(payload):
        return DeliveryResult(True, False, status_code=200)

    summary = await process_outbox_once(
        test_session_factory, sender, now=now, batch_size=10
    )

    await db_session.refresh(row)
    assert summary["sent"] == 1
    assert row.status == "sent"
