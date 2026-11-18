from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.deps import get_current_user
from app.database.connection import get_db
from app.database.models import Suppression
from app.services.suppressions import MAX_TTL_DAYS, normalize_expiry

router = APIRouter(tags=["Suppressions"])


class SuppressionCreate(BaseModel):
    rule_id: str = Field(..., min_length=1, max_length=128,
                        pattern=r"^[A-Za-z0-9_.:-]+$")
    expires_at: datetime
    reason: str = Field(..., min_length=8, max_length=2000)
    scope: Optional[Dict[str, Any]] = Field(default=None, max_length=12)


def _out(row: Suppression) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    expires = row.expires_at
    if expires and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    state = "revoked" if not row.active else ("expired" if expires <= now else "active")
    return {
        "id": row.id, "rule_id": row.rule_id, "scope": row.scope or {},
        "reason": row.reason, "created_by": row.created_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "expires_at": expires.isoformat() if expires else None,
        "active": bool(row.active), "state": state,
        "suppressed_count": row.suppressed_count,
        "last_suppressed_at": row.last_suppressed_at.isoformat() if row.last_suppressed_at else None,
    }


def _can_manage(user) -> bool:
    return (user.role or "").lower() in {"admin", "analyst"}


@router.get("")
async def list_suppressions(
    include_expired: bool = Query(False),
    rule_id: Optional[str] = Query(None, max_length=128),
    db: AsyncSession = Depends(get_db), user=Depends(get_current_user),
):
    query = select(Suppression).order_by(Suppression.created_at.desc()).limit(500)
    if rule_id:
        query = query.where(Suppression.rule_id == rule_id)
    rows = (await db.execute(query)).scalars().all()
    items = [_out(row) for row in rows]
    if not include_expired:
        items = [item for item in items if item["state"] == "active"]
    return {"items": items, "ttl_max_days": MAX_TTL_DAYS,
            "suppressed_total": sum(item["suppressed_count"] for item in items)}


@router.post("", status_code=201)
async def create_suppression(payload: SuppressionCreate, db: AsyncSession = Depends(get_db),
                             user=Depends(get_current_user)):
    if not _can_manage(user):
        raise HTTPException(status_code=403, detail="Suppression changes require analyst or admin role")
    try:
        expires = normalize_expiry(payload.expires_at)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    scope = payload.scope or {}
    if len(scope) > 12:
        raise HTTPException(status_code=422, detail="scope supports at most 12 fields")
    row = Suppression(
        rule_id=payload.rule_id, scope=scope, reason=payload.reason,
        created_by=user.id, expires_at=expires, active=True,
        suppressed_count=0,
    )
    db.add(row)
    await db.flush()
    await log_audit(db, action="suppression_create", resource="suppression",
                    resource_id=str(row.id), user_id=user.id,
                    details={"rule_id": row.rule_id, "expires_at": expires.isoformat(),
                             "scope": scope})
    await db.commit()
    await db.refresh(row)
    return _out(row)


@router.delete("/{suppression_id}")
async def revoke_suppression(suppression_id: int, db: AsyncSession = Depends(get_db),
                             user=Depends(get_current_user)):
    if not _can_manage(user):
        raise HTTPException(status_code=403, detail="Suppression changes require analyst or admin role")
    row = (await db.execute(select(Suppression).where(Suppression.id == suppression_id))).scalars().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Suppression not found")
    row.active = False
    await log_audit(db, action="suppression_revoke", resource="suppression",
                    resource_id=str(row.id), user_id=user.id,
                    details={"rule_id": row.rule_id})
    await db.commit()
    return {"status": "revoked", "id": row.id}
