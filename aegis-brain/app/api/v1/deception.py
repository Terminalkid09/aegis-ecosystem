"""Read-only deception view and delegated SSO for the Kraken microservice.

Kraken remains a separate service with its own database, users and session.
This module only exposes the minimum the Aegis console needs:

* a read-only overview of the events/alerts/incidents that originated there;
* a one-minute, single-use assertion that the browser can exchange at Kraken
  for a local Kraken session.

No Kraken-specific operation (sensors, sandbox, plugins, credentials) is
duplicated here. The assertion is signed with a dedicated key, not with the
Aegis access-token key.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
from uuid import uuid4

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.config import settings
from app.core.deps import get_current_user
from app.database.connection import get_db
from app.database.models import Alert, Incident, SiemEvent, User
from app.services import siem_store

router = APIRouter(tags=["Deception"])

KRAKEN_SSO_ISSUER = "aegis-brain"
KRAKEN_SSO_AUDIENCE = "kraken"


@router.get("/overview")
async def kraken_overview(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Kraken-originated data, read-only, already normalised by ingest."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    events = await siem_store.query_events(
        db,
        since=since,
        filters={"source_type": "kraken"},
        limit=limit,
    )

    event_count = int(await db.scalar(
        select(func.count(SiemEvent.id)).where(
            SiemEvent.source_type == "kraken",
            SiemEvent.time >= since,
        )
    ) or 0)
    unique_ips = int(await db.scalar(
        select(func.count(func.distinct(SiemEvent.src_ip))).where(
            SiemEvent.source_type == "kraken",
            SiemEvent.time >= since,
            SiemEvent.src_ip.is_not(None),
        )
    ) or 0)

    alert_rows = (await db.execute(
        select(Alert)
        .where(Alert.event_type == "DECEPTION", Alert.timestamp >= since)
        .order_by(Alert.timestamp.desc())
        .limit(limit)
    )).scalars().all()
    open_alerts = int(await db.scalar(
        select(func.count(Alert.id)).where(
            Alert.event_type == "DECEPTION",
            Alert.is_resolved.is_(False),
        )
    ) or 0)

    incident_rows = (await db.execute(
        select(Incident)
        .where(Incident.title.ilike("[KRAKEN]%"))
        .order_by(Incident.updated_at.desc())
        .limit(limit)
    )).scalars().all()

    return {
        "hours": hours,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "available": True,
        "sso_enabled": bool(settings.KRAKEN_SSO_ENABLED),
        "kraken_ui": "/kraken/",
        "stats": {
            "events": event_count,
            "unique_source_ips": unique_ips,
            "deception_alerts": len(alert_rows),
            "open_deception_alerts": open_alerts,
            "incidents": len(incident_rows),
        },
        "events": events["items"],
        "alerts": [
            {
                "id": a.id,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "severity": a.severity,
                "description": a.description,
                "process_name": a.process_name,
                "is_resolved": a.is_resolved,
            }
            for a in alert_rows
        ],
        "incidents": [
            {
                "id": i.id,
                "title": i.title,
                "severity": i.severity,
                "status": i.status,
                "created_at": i.created_at.isoformat() if i.created_at else None,
                "updated_at": i.updated_at.isoformat() if i.updated_at else None,
            }
            for i in incident_rows
        ],
    }


@router.post("/token")
async def issue_kraken_sso_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Issue a short-lived assertion for the browser's Kraken login exchange."""
    if not settings.KRAKEN_SSO_ENABLED:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Kraken SSO is not enabled",
        )
    secret = (settings.KRAKEN_SSO_SECRET or "").strip()
    if len(secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Kraken SSO is not configured",
        )

    now = datetime.now(timezone.utc)
    jti = str(uuid4())
    ttl = max(15, min(int(settings.KRAKEN_SSO_TTL_SECONDS), 300))
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": (user.role or "user").lower(),
        "iss": KRAKEN_SSO_ISSUER,
        "aud": KRAKEN_SSO_AUDIENCE,
        "iat": now,
        "exp": now + timedelta(seconds=ttl),
        "jti": jti,
    }
    token = jwt.encode(payload, secret, algorithm="HS256")

    await log_audit(
        db,
        action="kraken_sso_token_issued",
        resource="kraken",
        resource_id=jti,
        user_id=user.id,
        username=user.username,
        details={"ttl_seconds": ttl, "audience": KRAKEN_SSO_AUDIENCE},
        ip_address=request.client.host if request.client else None,
    )
    return {
        "token": token,
        "expires_in": ttl,
        "audience": KRAKEN_SSO_AUDIENCE,
        "sso_url": "/kraken/sso",
    }
