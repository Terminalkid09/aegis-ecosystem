from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database.connection import get_db
from app.database.models import Telemetry
from app.core.deps import get_current_user
import uuid

router = APIRouter(tags=["Telemetry History"])

@router.get("/history/{agent_id}")
async def get_telemetry_history(
    agent_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user),
):
    try:
        agent_uuid = uuid.UUID(agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent_id format")
    stmt = (
        select(Telemetry)
        .where(Telemetry.device_id == agent_uuid)
        .order_by(Telemetry.timestamp.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    return result.scalars().all()
