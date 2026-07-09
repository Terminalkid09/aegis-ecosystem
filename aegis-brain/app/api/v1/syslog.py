from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional
from app.database.connection import get_db
from app.database.models import SyslogEvent
from app.core.deps import get_current_user

router = APIRouter(tags=["Syslog"])

@router.get("")
@router.get("/events")
async def get_syslog_events(
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user),
    limit: int = Query(200, ge=1, le=1000),
    skip: int = Query(0, ge=0),
    hostname: Optional[str] = None,
    severity: Optional[int] = None,
):
    stmt = select(SyslogEvent)
    if hostname:
        stmt = stmt.where(SyslogEvent.hostname.ilike(f"%{hostname}%"))
    if severity is not None:
        stmt = stmt.where(SyslogEvent.severity == severity)
    stmt = stmt.order_by(desc(SyslogEvent.timestamp)).offset(skip).limit(limit)
    result = await db.execute(stmt)
    events = []
    for e in result.scalars().all():
        events.append({
            "id": e.id,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "facility": e.facility,
            "severity": e.severity,
            "hostname": e.hostname,
            "app_name": e.app_name,
            "message": e.message,
            "processed": e.processed,
        })
    return events
