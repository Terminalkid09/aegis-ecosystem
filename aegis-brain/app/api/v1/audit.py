from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional
from app.database.connection import get_db
from app.database.models import AuditLog
from app.core.deps import get_current_user

router = APIRouter(tags=["Audit"])

@router.get("")
@router.get("/logs")
async def get_audit_logs(
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user),
    limit: int = Query(100, ge=1, le=1000),
    skip: int = Query(0, ge=0),
    action: Optional[str] = None,
    resource: Optional[str] = None,
    username: Optional[str] = None,
):
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if resource:
        stmt = stmt.where(AuditLog.resource.ilike(f"%{resource}%"))
    if username:
        stmt = stmt.where(AuditLog.username.ilike(f"%{username}%"))
    stmt = stmt.order_by(desc(AuditLog.created_at)).offset(skip).limit(limit)
    result = await db.execute(stmt)
    logs = []
    for e in result.scalars().all():
        logs.append({
            "id": e.id,
            "user_id": e.user_id,
            "username": e.username,
            "action": e.action,
            "resource": e.resource,
            "resource_id": e.resource_id,
            "details": e.details,
            "ip_address": e.ip_address,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        })
    return logs
