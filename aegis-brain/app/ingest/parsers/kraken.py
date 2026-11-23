"""Parser del contratto Kraken → Aegis.

Kraken è un servizio separato: questo modulo è l'unico punto in cui il Brain
conosce la forma dei suoi eventi. Il parser non legge il DB Kraken e non
importa codice Kraken; traduce solo il JSON documentato in `docs/archive/PLAN_AEGIS_KRAKEN_HANDOFF.md` §5.3.

Regola di privacy: password, token e segreti non entrano mai in `raw`, `extra`,
`message` o negli alert. Il campo password del payload originale viene
redatto ricorsivamente prima di essere conservato.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from app.ingest.base import (
    ParserError,
    UnifiedEvent,
    as_int,
    bounded_raw,
    finalize,
    normalize_protocol,
    parse_timestamp,
)

_SECRET_KEYS = {"password", "passwd", "secret", "token", "authorization", "api_key"}
_MAX_EVENT_ID = 64


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[redacted]" if str(key).lower() in _SECRET_KEYS else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _stable_event_id(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ParserError("event_id is required")
    if len(raw) > _MAX_EVENT_ID:
        import hashlib
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return raw


class KrakenParser:
    name = "kraken"
    source_type = "kraken"

    def can_parse(self, payload: Any, meta: Dict[str, Any]) -> bool:
        return isinstance(payload, dict) and isinstance(payload.get("events"), list)

    def parse(self, payload: Any, meta: Dict[str, Any]) -> List[UnifiedEvent]:
        if isinstance(payload, list):
            rows = payload
        elif isinstance(payload, dict):
            rows = payload.get("events")
        else:
            raise ParserError("Kraken payload must be an object with an events list")
        if not isinstance(rows, list) or not rows:
            raise ParserError("Kraken payload contains no events")

        events: List[UnifiedEvent] = []
        now = datetime.now(timezone.utc)
        for row in rows:
            if not isinstance(row, dict):
                raise ParserError("each Kraken event must be an object")
            events.append(self._one(row, now))
        return events

    def _one(self, row: Dict[str, Any], now: datetime) -> UnifiedEvent:
        event_id = _stable_event_id(row.get("event_id"))
        occurred = parse_timestamp(row.get("occurred_at") or row.get("time"), default=now)
        host = _dict(row.get("host"))
        user = _dict(row.get("user"))
        network = _dict(row.get("network"))
        process = _dict(row.get("process"))
        raw = _dict(row.get("raw"))
        tags = row.get("tags") if isinstance(row.get("tags"), list) else []

        command_line = process.get("command_line")
        if command_line is not None:
            command_line = str(command_line)[:4096]
        process_name = process.get("name")
        if not process_name and command_line:
            process_name = str(command_line).split(maxsplit=1)[0][:255]

        sample_hash = raw.get("sample_sha256")
        safe_raw = _redact({**row, "raw": raw})
        extra = {
            "kraken": {
                "session_id": raw.get("session_id"),
                "sensor": raw.get("sensor"),
                "context": raw.get("context"),
                "run_id": raw.get("run_id"),
                "scenario_id": raw.get("scenario_id"),
                "topology_id": raw.get("topology_id"),
                "threat_level": raw.get("threat_level"),
                "geo": _redact(raw.get("geo") or {}),
                "iocs": _redact(raw.get("iocs") or []),
                "sample_sha256": sample_hash,
                "mitre": raw.get("mitre") or [],
                "late": (now - occurred).total_seconds() > 86400,
            },
            "original": safe_raw,
            "tags": tags,
        }

        return finalize(UnifiedEvent(
            time=occurred,
            source="kraken",
            source_type=self.source_type,
            event_id=event_id,
            ocsf_class_uid=3002,  # OCSF Authentication
            severity=str(row.get("severity") or raw.get("threat_level") or "MEDIUM"),
            hostname=host.get("hostname"),
            ip=host.get("ip"),
            user=user.get("name"),
            user_domain=user.get("domain"),
            process_name=str(process_name)[:255] if process_name else None,
            command_line=command_line,
            file_hash=str(sample_hash)[:128] if sample_hash else None,
            src_ip=network.get("src_ip"),
            src_port=as_int(network.get("src_port")),
            dst_ip=network.get("dst_ip"),
            dst_port=as_int(network.get("dst_port")),
            protocol=normalize_protocol(network.get("protocol")),
            category=str(row.get("category") or "intrusion_attempt")[:100],
            signature=str(raw.get("sensor") or "kraken")[:255],
            message=str(row.get("message") or f"{raw.get('sensor') or 'kraken'} session "
                        f"{raw.get('session_id') or event_id}")[:2000],
            raw=bounded_raw(safe_raw),
            extra=extra,
        ))
