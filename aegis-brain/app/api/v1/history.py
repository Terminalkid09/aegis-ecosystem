from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database.connection import get_db
from app.database.models import Telemetry
from app.core.deps import get_current_user
from typing import List, Dict, Any

router = APIRouter(tags=["Telemetry History"])

@router.get("/history/{agent_id}")
async def get_telemetry_history(
    agent_id: str, 
    limit: int = 50, 
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user),
):
    stmt = (
        select(Telemetry)
        .where(Telemetry.device_id == agent_id)
        .order_by(Telemetry.timestamp.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    return result.scalars().all()
