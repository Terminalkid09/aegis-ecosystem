from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.database.connection import get_db
from app.services.timeline import query_timeline

router = APIRouter(tags=["Timeline"])


@router.get("")
async def get_timeline(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(200, ge=1, le=500),
    sources: Optional[str] = Query(
        None,
        description="Comma-separated subset of siem,deception,alert,incident,telemetry",
        max_length=128,
    ),
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    return await query_timeline(db, hours=hours, limit=limit, sources=sources)
