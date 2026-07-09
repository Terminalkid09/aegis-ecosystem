from fastapi import Header, HTTPException, status, Depends, Request
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.config import settings
from app.core.security import decode_access_token, is_token_blacklisted
from app.database.connection import get_db
from app.database.models import User
from sqlalchemy import select


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
    return user


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Validate global API key (Aegis-Link gateway / tooling only — not dashboard UI)."""
    expected_key = settings.AEGIS_API_KEY
    if not expected_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API Key not configured on server"
        )
    if x_api_key != expected_key:
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
