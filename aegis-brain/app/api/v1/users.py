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
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.deps import KNOWN_ROLES, require_perm
from app.core.security import hash_password
from app.database.connection import get_db
from app.database.models import User

router = APIRouter(tags=["Users"])

USERNAME_RE = r"^[A-Za-z0-9._-]{3,150}$"


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=150, pattern=USERNAME_RE)
    email: str = Field(
        ..., min_length=5, max_length=255,
        pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(..., min_length=12, max_length=128)
    role: str = "user"
    active: bool = True


class UserPatch(BaseModel):
    active: bool | None = None
    role: str | None = None


class PasswordReset(BaseModel):
    password: str = Field(..., min_length=12, max_length=128)


async def _count_active_admins(db: AsyncSession) -> int:
    res = await db.execute(
        select(func.count(User.id)).where(User.role == "admin", User.active == True))
    return int(res.scalar() or 0)


def _user_out(u: User) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "email": u.email,
        "role": u.role,
        "active": bool(u.active),
        "oidc": bool(u.oidc_subject),
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


@router.get("")
async def list_users(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_perm("manage")),
):
    res = await db.execute(select(User).order_by(User.id))
    return {"users": [_user_out(u) for u in res.scalars().all()]}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_perm("manage")),
):
    role = (payload.role or "user").lower().strip()
    if role not in KNOWN_ROLES:
        raise HTTPException(status_code=422, detail="Unknown role")
    email = payload.email.strip().lower()
    username = payload.username.strip()
    if (await db.execute(select(User).where(User.email == email))).scalars().first():
        raise HTTPException(status_code=409, detail="Email already registered")
    if (await db.execute(select(User).where(User.username == username))).scalars().first():
        raise HTTPException(status_code=409, detail="Username already registered")

    user = User(
        username=username,
        email=email,
        password_hash=hash_password(payload.password),
        role=role,
        active=payload.active,
    )
    db.add(user)
    await db.flush()
    await log_audit(
        db, action="user_create", resource=f"user:{user.id}",
        details={"email": email, "username": username, "role": role,
                 "active": payload.active, "via": "api"},
        user_id=admin.id, username=admin.username,
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:500],
    )
    await db.commit()
    await db.refresh(user)
    return _user_out(user)


@router.post("/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    payload: PasswordReset,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_perm("manage")),
):
    target = await db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    target.password_hash = hash_password(payload.password)
    await log_audit(
        db, action="user_password_reset", resource=f"user:{target.id}",
        details={"email": target.email, "via": "api"},
        user_id=admin.id, username=admin.username,
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:500],
    )
    await db.commit()
    return {"status": "password_reset", "id": target.id}


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
