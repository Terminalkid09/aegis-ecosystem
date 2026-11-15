"""Client Kraken → Aegis per il contratto di deception.

Kraken non condivide DB né processi con il Brain: l'unico canale è questo POST
HTTP firmato. Il payload contiene solo i metadati dell'attacco; le password
tentate restano hash nel DB Kraken e non vengono mai serializzate qui.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from loguru import logger

from app.core.config import settings


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return moment.isoformat()
    return str(value) if value else datetime.now(timezone.utc).isoformat()


def build_attack_payload(event: Any, payload: Any) -> dict:
    """Build the wire event. Deliberately excludes `password` and credentials."""
    commands = [getattr(c, "command", "") for c in (getattr(event, "commands", None) or [])]
    attack_ip = getattr(event, "attacker_ip", None)
    sample_hash = None
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
                "context": "sensor",
                "iocs": [attack_ip] if attack_ip else [],
                "sample_sha256": sample_hash,
            },
            "tags": ["deception", "kraken"],
        }]
    }


async def publish_attack_event(event: Any, payload: Any) -> bool:
    """POST the signed event; fail-soft so an Aegis outage cannot drop the honeypot."""
    if not settings.AEGIS_INGEST_ENABLED:
        return False
    url = settings.AEGIS_INGEST_URL.rstrip("/") + "/api/v1/ingest/kraken"
    body = json.dumps(build_attack_payload(event, payload), separators=(",", ":")).encode("utf-8")
    signature = hmac.new(
        settings.AEGIS_INGEST_SECRET.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": settings.AEGIS_INGEST_KEY,
        "X-Kraken-Signature": f"sha256={signature}",
    }
    try:
        async with httpx.AsyncClient(timeout=settings.AEGIS_INGEST_TIMEOUT_S) as client:
            response = await client.post(url, content=body, headers=headers)
        if response.status_code >= 400:
            logger.warning(f"Aegis ingest rejected Kraken event: HTTP {response.status_code}")
            return False
        return True
    except Exception as exc:
        logger.warning(f"Aegis ingest unavailable: {type(exc).__name__}")
        return False
