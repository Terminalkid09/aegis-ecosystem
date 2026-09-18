"""Ricerca sugli eventi normalizzati.

Filtro strutturato + ricerca libera. La sintassi è volutamente esplicita e
chiusa (allowlist di campi lato server): nessun nome di colonna, nessun
operatore e nessun `ORDER BY` arriva mai dal client, quindi non esiste una via
per l'injection via query builder.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.database.connection import get_db
from app.services import siem_store


router = APIRouter(tags=["SIEM Search"])


class SearchRequest(BaseModel):
    """Corpo della ricerca. `filters` è campo → valore (o lista di valori)."""

    text: Optional[str] = Field(None, max_length=256)
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    hours: Optional[int] = Field(None, ge=1, le=720,
                                 description="Alternativa a `since`: ultime N ore")
    filters: Dict[str, Any] = Field(default_factory=dict)
    limit: int = Field(100, ge=1, le=500)
    offset: int = Field(0, ge=0)
    order: str = Field("desc", pattern="^(asc|desc)$")


@router.post("/events")
async def search_events(payload: SearchRequest, db: AsyncSession = Depends(get_db),
                        user=Depends(get_current_user)):
    since = payload.since
    if since is None and payload.hours:
        since = datetime.now(timezone.utc) - timedelta(hours=payload.hours)
    if payload.until is not None and payload.until.tzinfo is None:
        payload.until = payload.until.replace(tzinfo=timezone.utc)
    if since is not None and since.tzinfo is None:
        since = since.replace(tzinfo=timezone.utc)
    return await siem_store.query_events(
        db, since=since, until=payload.until, text=payload.text,
        filters=payload.filters, limit=payload.limit, offset=payload.offset,
        order=payload.order,
    )


@router.get("/events")
async def search_events_simple(
    q: Optional[str] = Query(None, max_length=256, description="Ricerca libera"),
    source: Optional[str] = Query(None, max_length=128),
    severity: Optional[str] = Query(None, max_length=16),
    src_ip: Optional[str] = Query(None, max_length=45),
    hostname: Optional[str] = Query(None, max_length=255),
    user_name: Optional[str] = Query(None, alias="user", max_length=255),
    hours: Optional[int] = Query(None, ge=1, le=720),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    order: str = Query("desc", pattern="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    current=Depends(get_current_user),
):
    """Variante GET per link condivisibili e per la UI.

    Comoda per chi vuole aprire una ricerca dal browser senza costruire un POST.
    """
    filters = {"source": source, "severity": severity, "src_ip": src_ip,
               "hostname": hostname, "user": user_name}
    since = datetime.now(timezone.utc) - timedelta(hours=hours) if hours else None
    return await siem_store.query_events(
        db, since=since, text=q, filters=filters, limit=limit, offset=offset, order=order)


@router.get("/stats")
async def search_stats(hours: int = Query(24, ge=1, le=720),
                       db: AsyncSession = Depends(get_db),
                       user=Depends(get_current_user)):
    return await siem_store.event_stats(db, hours=hours)


@router.get("/fields")
async def searchable_fields(user=Depends(get_current_user)):
    """Campi filtrabili con la descrizione, per aiutare chi scrive la query."""
    labels = {
        "source": "Configured log source name",
        "source_type": "Parser family (windows_event, zeek, suricata, firewall…)",
        "severity": "INFO | LOW | MEDIUM | HIGH | CRITICAL",
        "hostname": "Host that generated the event",
        "ip": "Event IP address",
        "user": "User involved",
        "src_ip": "Source IP",
        "dst_ip": "Destination IP",
        "src_port": "Source port",
        "dst_port": "Destination port",
        "protocol": "Normalized protocol (tcp/udp/icmp)",
        "process_name": "Process name",
        "file_name": "File name",
        "file_path": "File path",
        "domain": "Application domain/host",
        "dns_query": "DNS query",
        "signature": "IDS or provider signature",
        "signature_id": "Signature ID / EventID",
        "category": "Log source category",
        "message_id": "EventID / message id",
        "url": "Requested URL",
        "http_method": "HTTP method",
        "http_status": "HTTP status code",
        "event_id": "Single event identifier (dedup)",
    }
    return {"fields": [{"field": f, "description": labels.get(f, "")}
                       for f in sorted(siem_store.FILTERABLE_FIELDS)]}
