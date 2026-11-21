import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.database.models import Alert, DeceptionSession, Incident, IncidentAlert, SiemEvent


def _kraken_body(event_id: str, *, occurred_at: str | None = None,
                 password: str = "plain-secret", context: str = "sensor") -> bytes:
    event = {
        "event_id": event_id,
        "occurred_at": occurred_at or datetime.now(timezone.utc).isoformat(),
        "host": {"hostname": "kraken-node-01", "os": "linux"},
        "source": "kraken",
        "category": "intrusion_attempt",
        "action": "login_attempt",
        "outcome": "failure",
        "severity": "high",
        "user": {"name": "root"},
        "network": {
            "src_ip": "45.9.20.7", "src_port": 51244,
            "dst_ip": "203.0.113.10", "dst_port": 22, "protocol": "ssh",
        },
        "process": {"command_line": "uname -a"},
        "raw": {
            "sensor": "ssh", "session_id": event_id, "threat_level": "high",
            "geo": {"country": "RU"}, "iocs": ["45.9.20.7"],
            "password": password, "context": context,
            "run_id": "run-lab-1" if context == "lab" else None,
        },
        "tags": ["deception", "kraken"],
    }
    return json.dumps({"events": [event]}, separators=(",", ":")).encode()


def _headers(body: bytes, secret: str, key: str = "test-global-key") -> dict:
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return {
        "X-Api-Key": key,
        "X-Kraken-Signature": f"sha256={signature}",
        "Content-Type": "application/json",
    }


@pytest.fixture
def kraken_settings(monkeypatch):
    secret = "k" * 40
    monkeypatch.setattr(settings, "AEGIS_API_KEY", "test-global-key")
    monkeypatch.setattr(settings, "KRAKEN_INGEST_ENABLED", True)
    monkeypatch.setattr(settings, "KRAKEN_INGEST_SECRET", secret)
    return secret


@pytest.mark.asyncio
async def test_kraken_event_creates_stored_event_alert_and_incident(
    client, db_session, kraken_settings
):
    event_id = f"kraken:test:{uuid.uuid4().hex}:ssh"
    body = _kraken_body(event_id)
    response = await client.post(
        "/api/v1/ingest/kraken",
        content=body,
        headers=_headers(body, kraken_settings),
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["stored"] == 1
    # One event can legitimately match more than one deception rule (SSH
    # credential access and post-auth command), but the fallback must not add
    # another alert on top: every id must belong to the same event's incident.
    assert data["alerts"] >= 1
    assert len(data["alert_ids"]) == data["alerts"]
    assert data["incident_id"] is not None

    stored = (await db_session.execute(
        select(SiemEvent).where(SiemEvent.event_id == event_id)
    )).scalars().one()
    assert stored.source == "kraken"
    assert stored.source_type == "kraken"
    assert stored.src_ip == "45.9.20.7"
    assert "plain-secret" not in json.dumps(stored.extra)

    alerts = (await db_session.execute(
        select(Alert).where(Alert.id.in_(data["alert_ids"]))
    )).scalars().all()
    assert alerts and all(alert.event_type == "DECEPTION" for alert in alerts)
    assert all("plain-secret" not in alert.description for alert in alerts)
    assert all("plain-secret" not in json.dumps(alert.evidence) for alert in alerts)

    incident = await db_session.get(Incident, data["incident_id"])
    assert incident is not None
    links = (await db_session.execute(
        select(IncidentAlert).where(IncidentAlert.incident_id == incident.id)
    )).scalars().all()
    assert links
    assert {link.alert_id for link in links} == set(data["alert_ids"])

    session = (await db_session.execute(
        select(DeceptionSession).where(DeceptionSession.session_id == event_id)
    )).scalars().one()
    assert session.context == "sensor"
    assert session.incident_id == incident.id


@pytest.mark.asyncio
async def test_lab_context_is_preserved_and_marked_shadow(
    client, db_session, kraken_settings
):
    event_id = f"kraken:lab:{uuid.uuid4().hex}:ssh"
    body = _kraken_body(event_id, context="lab")
    response = await client.post(
        "/api/v1/ingest/kraken", content=body,
        headers=_headers(body, kraken_settings),
    )
    assert response.status_code == 200, response.text
    stored = (await db_session.execute(
        select(SiemEvent).where(SiemEvent.event_id == event_id)
    )).scalars().one()
    assert stored.extra["kraken"]["context"] == "lab"
    session = (await db_session.execute(
        select(DeceptionSession).where(DeceptionSession.session_id == event_id)
    )).scalars().one()
    assert session.context == "lab"
    assert session.status == "shadow"
    assert session.run_id == "run-lab-1"


@pytest.mark.asyncio
async def test_kraken_retry_is_idempotent(client, db_session, kraken_settings):
    event_id = f"kraken:test:{uuid.uuid4().hex}:ssh"
    body = _kraken_body(event_id)
    headers = _headers(body, kraken_settings)
    first = await client.post("/api/v1/ingest/kraken", content=body, headers=headers)
    second = await client.post("/api/v1/ingest/kraken", content=body, headers=headers)
    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["duplicates"] == 1
    assert second.json()["stored"] == 0
    count = (await db_session.execute(
        select(SiemEvent).where(SiemEvent.event_id == event_id)
    )).scalars().all()
    assert len(count) == 1


@pytest.mark.asyncio
async def test_kraken_rejects_bad_hmac(client, kraken_settings):
    body = _kraken_body(f"kraken:test:{uuid.uuid4().hex}:ssh")
    headers = _headers(body, kraken_settings)
    headers["X-Kraken-Signature"] = "sha256=" + ("0" * 64)
    response = await client.post("/api/v1/ingest/kraken", content=body, headers=headers)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_kraken_rejects_old_event(client, kraken_settings):
    old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    body = _kraken_body(f"kraken:test:{uuid.uuid4().hex}:ssh", occurred_at=old)
    response = await client.post(
        "/api/v1/ingest/kraken",
        content=body,
        headers=_headers(body, kraken_settings),
    )
    assert response.status_code == 422
