import hmac
from fastapi import Header, HTTPException, status, Depends, Request
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.core.security import decode_access_token, is_token_blacklisted
from app.database.connection import get_db
from app.database.models import User
from sqlalchemy import select


def require_roles(*roles: str):
    """Create a dependency for endpoints that mutate SOC state."""
    allowed = {role.lower() for role in roles}

    async def _dependency(user=Depends(get_current_user)):
        if (user.role or "user").lower() not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return _dependency


# M7 Fase 8: matrice ruoli → permessi. I ruoli legacy restano validi:
# "user" legge come viewer; le restrizioni esistenti NON si allentano qui,
# i nuovi endpoint usano require_perm. Enforcement completo viewer/auditor
# read-only sugli endpoint legacy = hardening Fase 10 (suite congelata).
ROLE_PERMISSIONS = {
    "viewer": frozenset({"read"}),
    "user": frozenset({"read"}),  # legacy = viewer
    "auditor": frozenset({"read", "audit"}),
    "responder": frozenset({"read", "respond"}),
    "analyst": frozenset({"read", "audit", "respond", "triage", "deploy", "rules"}),
    "admin": frozenset({"read", "audit", "respond", "triage", "deploy", "rules", "manage"}),
}

KNOWN_ROLES = tuple(ROLE_PERMISSIONS)


def has_perm(role: str | None, perm: str) -> bool:
    """True se il ruolo ha il permesso (sconosciuto = niente). Puro."""
    return perm in ROLE_PERMISSIONS.get((role or "").lower(), frozenset())


def require_perm(*perms: str):
    """Dependency: basta UNO dei permessi elencati."""
    wanted = set(perms)

    async def _dependency(user=Depends(get_current_user)):
        role = (user.role or "user").lower()
        if not (ROLE_PERMISSIONS.get(role, frozenset()) & wanted):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return _dependency


def _extract_token(authorization: Optional[str], request: Request) -> Optional[str]:
    """Extract JWT from Authorization header or httpOnly cookie."""
    if authorization and authorization.startswith("Bearer "):
        return authorization[7:]
    cookie_token = request.cookies.get("aegis_token")
    if cookie_token:
        return cookie_token
    return None


async def _validate_token(token: str, db: AsyncSession) -> User:
    """Decode + blacklist-check + load user from a JWT."""
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    jti = payload.get("jti")
    if await is_token_blacklisted(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    # Account disattivato dall'admin: il token esistente perde valore subito,
    # senza attendere la sua scadenza naturale.
    if not user.active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account disabled")
    return user


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Validate global API key (Aegis-Link gateway / tooling only — not dashboard UI)."""
    expected_key = settings.AEGIS_API_KEY
    if not expected_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API Key not configured on server"
        )
    # Constant-time comparison to prevent timing attacks
    # (None-safe: missing header must be 403, never TypeError -> 500)
    if not x_api_key or not hmac.compare_digest(x_api_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Invalid or missing X-Api-Key"
        )
    return x_api_key


async def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    token = _extract_token(authorization, request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication. Provide Authorization header or aegis_token cookie.",
        )
    return await _validate_token(token, db)


async def get_optional_user(
    authorization: Optional[str] = Header(None),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
):
    token = _extract_token(authorization, request)
    if not token:
        return None
    try:
        return await _validate_token(token, db)
    except HTTPException:
        return None
