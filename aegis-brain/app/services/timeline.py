"""Timeline unificata SOC.

Cinque sorgenti, cinque query indipendenti sugli indici temporali, un solo
ordinamento in memoria. Non si fa una UNION SQL gigante perché le tabelle hanno
forme diverse e un errore su una sorgente non deve svuotare le altre. Il limite
è applicato a ogni sorgente e poi alla lista finale: una dashboard non deve
caricare 10.000 righe per mostrarne 200.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Alert, Agent, Incident, SiemEvent, Telemetry

SOURCE_NAMES = ("siem", "deception", "alert", "incident", "telemetry")


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _item(
    *, source: str, item_id: str, moment: datetime | None, severity: str,
    title: str, detail: str = "", host: str | None = None,
    ip: str | None = None, page: str = "search", ref: Any = None,
) -> Dict[str, Any]:
    return {
        "id": f"{source}:{item_id}",
        "source": source,
        "time": _iso(moment),
        "_moment": moment,
        "severity": (severity or "INFO").upper(),
        "title": title[:300],
        "detail": detail[:1000],
        "host": host,
        "ip": ip,
        "link": {"page": page, "id": ref if ref is not None else item_id},
    }


def _normalise_sources(raw: Optional[str | Iterable[str]]) -> list[str]:
    if raw is None or raw == "":
        return list(SOURCE_NAMES)
    if isinstance(raw, str):
        values = [part.strip().lower() for part in raw.split(",")]
    else:
        values = [str(part).strip().lower() for part in raw]
    chosen = [value for value in values if value in SOURCE_NAMES]
    return chosen or list(SOURCE_NAMES)


async def query_timeline(
    db: AsyncSession,
    *,
    hours: int = 24,
    limit: int = 200,
    sources: Optional[str | Iterable[str]] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    since = (now or datetime.now(timezone.utc)) - timedelta(hours=max(1, min(int(hours), 720)))
    limit = max(1, min(int(limit), 500))
    chosen = _normalise_sources(sources)
    items: List[Dict[str, Any]] = []

    if "siem" in chosen:
        rows = (await db.execute(
            select(SiemEvent)
            .where(SiemEvent.time >= since, SiemEvent.source_type != "kraken")
            .order_by(SiemEvent.time.desc())
            .limit(limit)
        )).scalars().all()
        for row in rows:
            items.append(_item(
                source="siem", item_id=str(row.id), moment=row.time,
                severity=row.severity,
                title=row.message or f"{row.source_type} event",
                detail=f"{row.source or 'source'} · {row.event_id}",
                host=row.hostname, ip=row.src_ip, page="search", ref=row.id,
            ))

    if "deception" in chosen:
        rows = (await db.execute(
            select(SiemEvent)
            .where(SiemEvent.time >= since, SiemEvent.source_type == "kraken")
            .order_by(SiemEvent.time.desc())
            .limit(limit)
        )).scalars().all()
        for row in rows:
            raw = (row.extra or {}).get("kraken") or {}
            context = raw.get("context") or "sensor"
            items.append(_item(
                source="deception", item_id=str(row.id), moment=row.time,
                severity=row.severity,
                title=f"Kraken {raw.get('sensor') or 'sensor'}: {row.message or 'session'}",
                detail=f"session={raw.get('session_id') or '—'} · context={context}",
                host=row.hostname, ip=row.src_ip, page="kraken", ref=row.id,
            ))

    if "alert" in chosen:
        rows = (await db.execute(
            select(Alert).where(Alert.timestamp >= since)
            .order_by(Alert.timestamp.desc()).limit(limit)
        )).scalars().all()
        for row in rows:
            items.append(_item(
                source="alert", item_id=str(row.id), moment=row.timestamp,
                severity=row.severity, title=row.description,
                detail=f"{row.event_type} · {row.process_name}",
                host=row.process_name, page="alerts", ref=row.id,
            ))

    if "incident" in chosen:
        rows = (await db.execute(
            select(Incident).where(Incident.updated_at >= since)
            .order_by(Incident.updated_at.desc()).limit(limit)
        )).scalars().all()
        for row in rows:
            items.append(_item(
                source="incident", item_id=str(row.id), moment=row.updated_at,
                severity=row.severity, title=row.title,
                detail=f"status={row.status} · agent={row.agent_id or '—'}",
                page="incidents", ref=row.id,
            ))

    if "telemetry" in chosen:
        rows = (await db.execute(
            select(Telemetry, Agent.hostname)
            .outerjoin(Agent, Agent.agent_id == Telemetry.device_id)
            .where(Telemetry.timestamp >= since)
            .order_by(Telemetry.timestamp.desc()).limit(limit)
        )).all()
        for row, hostname in rows:
            items.append(_item(
                source="telemetry", item_id=str(row.id), moment=row.timestamp,
                severity="INFO", title=f"Heartbeat {hostname or row.device_id}",
                detail=f"cpu={row.cpu_usage if row.cpu_usage is not None else '—'}% · "
                       f"ram={row.ram_usage if row.ram_usage is not None else '—'}%",
                host=hostname or str(row.device_id), ip=row.ip_local,
                page="agents", ref=str(row.device_id),
            ))

    items.sort(key=lambda item: item["_moment"] or datetime.min.replace(tzinfo=timezone.utc),
               reverse=True)
    counts: Dict[str, int] = {name: 0 for name in SOURCE_NAMES}
    for item in items:
        counts[item["source"]] = counts.get(item["source"], 0) + 1
    for item in items:
        item.pop("_moment", None)
    return {
        "window_hours": hours,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sources": list(SOURCE_NAMES),
        "selected_sources": chosen,
        "counts": counts,
        "items": items[:limit],
    }
