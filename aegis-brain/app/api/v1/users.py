"""Gestione account (solo admin): elenco, disattivazione, riattivazione, ruolo.

Perché esiste: il modello User ha sempre avuto il flag `active`, ma nessuno lo
controllava — un account disattivato continuava a operare (login accettato e
token validi fino a scadenza naturale). Ora:
- il login rifiuta gli account non attivi (403 "Account disabled");
- la validazione del token rifiuta i token di account non attivi, quindi la
  disattivazione revoca l'accesso *immediatamente*, non alla scadenza del JWT;
- da qui un admin elenca e gestisce gli account, con auto-protezione
  last-admin: il sistema non può restare senza nessun admin attivo.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.deps import require_perm, KNOWN_ROLES
from app.database.connection import get_db
from app.database.models import User

router = APIRouter(tags=["Users"])


class UserPatch(BaseModel):
    active: Optional[bool] = None
    role: Optional[str] = None


async def _count_active_admins(db: AsyncSession) -> int:
    res = await db.execute(
        select(func.count(User.id)).where(User.role == "admin", User.active == True))  # noqa: E712
    return int(res.scalar() or 0)


def _user_out(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "active": bool(u.active),
    }


@router.get("")
async def list_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_perm("manage")),
):
    res = await db.execute(select(User).order_by(User.id))
    return {"users": [_user_out(u) for u in res.scalars().all()]}


@router.patch("/{user_id}")
async def update_user(
    user_id: int,
    payload: UserPatch,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_perm("manage")),
):
    if payload.active is None and payload.role is None:
        raise HTTPException(status_code=422, detail="Nothing to update")

    if payload.role is not None and payload.role.lower() not in KNOWN_ROLES:
        raise HTTPException(status_code=422, detail="Unknown role")

    res = await db.execute(select(User).where(User.id == user_id))
    target = res.scalars().first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    will_stop_being_admin = target.role == "admin" and target.active and (
        payload.active is False or (payload.role is not None and payload.role.lower() != "admin")
    )
    if will_stop_being_admin and await _count_active_admins(db) <= 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Cannot demote or disable the last active admin",
        )

    changed: list[str] = []
    if payload.role is not None and payload.role.lower() != target.role:
        target.role = payload.role.lower()
        changed.append(f"role->{target.role}")
    if payload.active is not None and bool(target.active) != payload.active:
        target.active = payload.active
        changed.append(f"active->{payload.active}")

    if not changed:
        return _user_out(target)

    await db.commit()
    await db.refresh(target)

    await log_audit(
        db,
        action="user_update",
        resource=f"user:{target.id}",
        details={"changes": changed, "target_email": target.email},
        user_id=admin.id,
        username=admin.username,
    )
    return _user_out(target)
