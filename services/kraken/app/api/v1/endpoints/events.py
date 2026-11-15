from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from app.db.session import get_db
from app.schemas.schemas import AttackEventOut, AttackEventSummary, SensorEventIn, DashboardStats
from app.services.attack_service import (
    ingest_sensor_event, get_events, get_event_by_session, get_dashboard_stats,
)
from app.api.v1.endpoints.deps import get_current_user
from app.core.security import verify_internal_api_key
from app.core.limiter import limiter
from app.core.config import settings

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/ingest", response_model=AttackEventOut, status_code=201)
@limiter.limit(settings.RATE_LIMIT_INGEST)
async def ingest(
    request: Request,
    payload: SensorEventIn,
    db: AsyncSession = Depends(get_db),
    _key: str = Depends(verify_internal_api_key),
):
    """Receive telemetry from sensors. Requires X-Internal-API-Key header."""
    from sqlalchemy.exc import IntegrityError
    try:
        return await ingest_sensor_event(db, payload)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Duplicate session_id")


@router.get("/stats", response_model=DashboardStats)
async def stats(
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    return await get_dashboard_stats(db)


@router.get("/", response_model=List[AttackEventSummary])
async def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    sensor_type: Optional[str] = Query(None, max_length=32),
    attacker_ip: Optional[str] = Query(None, max_length=45),
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    return await get_events(db, skip=skip, limit=limit, sensor_type=sensor_type, attacker_ip=attacker_ip)


@router.get("/{session_id}", response_model=AttackEventOut)
async def get_event(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    _user=Depends(get_current_user),
):
    event = await get_event_by_session(db, session_id)
    if not event:
        raise HTTPException(status_code=404, detail="Session not found.")
    return event
