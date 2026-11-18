"""Client Kraken → Aegis per il contratto di deception.

Kraken non condivide DB né processi con il Brain: l'unico canale è il POST HTTP
firmato. Il payload contiene solo i metadati dell'attacco; le password tentate
restano hash nel DB Kraken e non vengono mai serializzate qui.

La consegna non avviene più in linea con l'ingest: `enqueue_attack_event` scrive
una riga nella tabella `outbox` nella stessa transazione dell'evento. Il worker
in `app/services/outbox.py` la spedisce e ritenta, così un Brain spento non
perde l'evento lato Aegis.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx
from loguru import logger
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import NoInspectionAvailable
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import NO_VALUE

from app.core.config import settings
from app.models.models import Outbox


@dataclass(frozen=True)
class DeliveryResult:
    """Esito di un tentativo di consegna.

    `retryable` distingue un guasto temporaneo (Rete, 5xx, 429) da un payload
    che il Brain rifiuta stabilmente (4xx): il secondo non va ritentato.
    """

    ok: bool
    retryable: bool
    status_code: int | None = None
    error: str | None = None


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=UTC)
        return moment.isoformat()
    return str(value) if value else datetime.now(UTC).isoformat()


def _loaded_relation(event: Any, name: str) -> list[Any] | None:
    """Return a loaded ORM relationship without triggering a lazy load.

    `ingest_sensor_event` calls this before commit, when relationships may not
    be loaded. Accessing them naively raises MissingGreenlet in async code.
    """
    try:
        state = sa_inspect(event)
    except NoInspectionAvailable:
        return None
    try:
        value = getattr(state.attrs, name).loaded_value
    except (AttributeError, KeyError):
        return None
    return [] if value is NO_VALUE else list(value or [])


def _commands(event: Any, payload: Any) -> list[str]:
    loaded = _loaded_relation(event, "commands")
    if loaded is None:
        # Plain object (unit tests, adapters): read it directly.
        loaded = getattr(event, "commands", None) or []
    commands = [getattr(c, "command", "") for c in loaded]
    if commands:
        return commands
    # During ingest the AttackCommand rows are pending and the relationship may
    # still be empty. The validated sensor payload is the same source of truth.
    return [str(c) for c in (getattr(payload, "commands", None) or [])]


def build_attack_payload(event: Any, payload: Any) -> dict:
    """Build the wire event. Deliberately excludes `password` and credentials."""
    commands = _commands(event, payload)
    attack_ip = getattr(event, "attacker_ip", None)
    sample_hash = None
    samples = _loaded_relation(event, "malware_samples")
    if samples is None:
        samples = getattr(event, "malware_samples", None) or []
    if samples:
        sample_hash = getattr(samples[0], "sha256", None)

    return {
        "events": [{
            "event_id": (f"kraken:{getattr(event, 'sensor_type', 'sensor')}:"
                         f"{getattr(event, 'session_id', '')}:0")[:64],
            "occurred_at": _iso(getattr(event, "timestamp_start", None)),
            "host": {"hostname": "kraken-node", "os": "linux"},
            "source": "kraken",
            "category": "intrusion_attempt",
            "action": "login_attempt",
            "outcome": "failure",
            "severity": "HIGH" if getattr(event, "is_known_threat", False) else "MEDIUM",
            "user": {"name": getattr(payload, "username", None)},
            "network": {
                "src_ip": attack_ip,
                "src_port": getattr(event, "attacker_port", None),
                "dst_port": getattr(event, "sensor_port", None),
                "protocol": getattr(event, "sensor_type", None),
            },
            "process": {"command_line": commands[0] if commands else None},
            "raw": {
                "sensor": getattr(event, "sensor_type", None),
                "session_id": getattr(event, "session_id", None),
                "threat_level": "high" if getattr(event, "is_known_threat", False) else "medium",
                "geo": {
                    "country": getattr(event, "country", None),
                    "city": getattr(event, "city", None),
                    "asn": getattr(event, "asn", None),
                },
                "context": getattr(payload, "context", "sensor") or "sensor",
                "run_id": getattr(payload, "run_id", None),
                "scenario_id": getattr(payload, "scenario_id", None),
                "topology_id": getattr(payload, "topology_id", None),
                "iocs": [attack_ip] if attack_ip else [],
                "sample_sha256": sample_hash,
            },
            "tags": ["deception", "kraken"],
        }]
    }


def _body(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def enqueue_attack_event(db: AsyncSession, event: Any, payload: Any) -> Outbox | None:
    """Queue the signed event in the same transaction as the attack record.

    Returns ``None`` when forwarding is disabled, so a lab/standalone Kraken
    does not accumulate rows it will never send.
    """
    if not settings.AEGIS_INGEST_ENABLED:
        return None
    wire = build_attack_payload(event, payload)
    entry = Outbox(
        event_id=wire["events"][0]["event_id"],
        payload=wire,
        status="pending",
        attempts=0,
        next_attempt_at=datetime.now(UTC),
    )
    db.add(entry)
    return entry


def _headers(body: bytes) -> dict[str, str]:
    signature = hmac.new(
        settings.AEGIS_INGEST_SECRET.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Api-Key": settings.AEGIS_INGEST_KEY,
        "X-Kraken-Signature": f"sha256={signature}",
    }


async def send_payload(payload: dict) -> DeliveryResult:
    """POST one outbox payload. Never raises for network or Aegis errors."""
    if not settings.AEGIS_INGEST_ENABLED:
        return DeliveryResult(False, True, error="Aegis ingest disabled")

    url = settings.AEGIS_INGEST_URL.rstrip("/") + "/api/v1/ingest/kraken"
    body = _body(payload)
    try:
        async with httpx.AsyncClient(timeout=settings.AEGIS_INGEST_TIMEOUT_S) as client:
            response = await client.post(url, content=body, headers=_headers(body))
    except httpx.HTTPError as exc:
        logger.warning(f"Aegis ingest unavailable: {type(exc).__name__}")
        return DeliveryResult(False, True, error=type(exc).__name__)

    if 200 <= response.status_code < 300:
        return DeliveryResult(True, False, status_code=response.status_code)

    detail = (response.text or "")[:300]
    logger.warning(f"Aegis ingest rejected Kraken event: HTTP {response.status_code}")
    retryable = response.status_code in (408, 425, 429) or response.status_code >= 500
    return DeliveryResult(
        False,
        retryable,
        status_code=response.status_code,
        error=detail or f"HTTP {response.status_code}",
    )
