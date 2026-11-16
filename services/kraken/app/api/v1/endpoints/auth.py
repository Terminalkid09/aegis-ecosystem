import secrets
import time
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.db.session import get_db
from app.models.models import User
from app.schemas.schemas import LoginRequest, TokenResponse, RefreshRequest, SsoRequest, UserCreate, UserOut
from app.core.security import (
    verify_password, hash_password,
    create_access_token, create_refresh_token,
    decode_access_payload, decode_refresh_payload, decode_sso_assertion,
)
from app.core.limiter import limiter
from app.core.config import settings
from app.db.redis import consume_refresh_jti, consume_sso_jti

router = APIRouter(prefix="/auth", tags=["auth"])


def _cookie_path() -> str:
    """Scope session cookies to the mounted prefix (or / when standalone)."""
    return settings.base_path() or "/"


def _issue_session(response: Response, username: str) -> TokenResponse:
    access_token = create_access_token(subject=username)
    refresh_token = create_refresh_token(subject=username)
    path = _cookie_path()
    response.set_cookie(
        key="kraken_token",
        value=access_token,
        httponly=True,
        samesite="strict",
        secure=not settings.DEBUG,
        max_age=settings.JWT_ACCESS_EXPIRE_MINUTES * 60,
        path=path,
    )
    response.set_cookie(
        key="kraken_refresh",
        value=refresh_token,
        httponly=True,
        samesite="strict",
        secure=not settings.DEBUG,
        max_age=settings.JWT_REFRESH_EXPIRE_MINUTES * 60,
        path=path,
    )
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def login(request: Request, response: Response, payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()
    if not user or not user.is_active or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")
    return _issue_session(response, user.username)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("10/minute")
async def refresh(request: Request, response: Response, payload: RefreshRequest, db: AsyncSession = Depends(get_db)):
    token_payload = decode_refresh_payload(payload.refresh_token)
    if not token_payload or not token_payload.get("sub") or not token_payload.get("jti"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token.")
    ttl = max(int(token_payload.get("exp", time.time()) - time.time()), 1)
    if not await consume_refresh_jti(token_payload["jti"], ttl):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token already used or revoked.")
    username = token_payload["sub"]
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive.")
    return _issue_session(response, user.username)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response):
    token = request.cookies.get("kraken_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if token:
        payload = decode_access_payload(token)
        if payload and payload.get("jti"):
            exp = payload.get("exp")
            now = time.time()
            ttl = max(int(exp - now), 0) if exp else 0
            from app.db.redis import blacklist_token
            await blacklist_token(payload["jti"], ttl)
    refresh_token = request.cookies.get("kraken_refresh")
    if refresh_token:
        refresh_payload = decode_refresh_payload(refresh_token)
        if refresh_payload and refresh_payload.get("jti"):
            exp = refresh_payload.get("exp")
            ttl = max(int(exp - time.time()), 0) if exp else 0
            from app.db.redis import blacklist_token
            await blacklist_token(refresh_payload["jti"], ttl)
    for path in {_cookie_path(), "/"}:
        response.delete_cookie("kraken_token", path=path)
        response.delete_cookie("kraken_refresh", path=path)
    return None


@router.post("/sso", response_model=TokenResponse)
@limiter.limit("20/minute")
async def sso_exchange(
    request: Request,
    response: Response,
    payload: SsoRequest,
    db: AsyncSession = Depends(get_db),
):
    """Exchange a Brain assertion for a real local Kraken session.

    The assertion is valid for one minute and can be used once. The local user
    is namespaced (`aegis:<brain-username>`) so it can never shadow a native
    Kraken account; no password is ever set for it.
    """
    claims = decode_sso_assertion(payload.token)
    if not claims or not claims.get("jti") or not claims.get("username"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired SSO assertion.",
        )
    ttl = max(int(claims.get("exp", time.time()) - time.time()), 1)
    if not await consume_sso_jti(str(claims["jti"]), ttl):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSO assertion already used or revoked.",
        )

    username = f"aegis:{str(claims['username'])[:56]}"
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    role = str(claims.get("role") or "user").lower()
    if user is None:
        user = User(
            username=username,
            # Unguessable random secret: this account only authenticates via SSO.
            hashed_password=hash_password(secrets.token_urlsafe(48)),
            is_admin=role == "admin",
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
    elif not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled.")
    elif user.is_admin != (role == "admin"):
        user.is_admin = role == "admin"
        await db.commit()

    return _issue_session(response, user.username)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def register(request: Request, payload: UserCreate, db: AsyncSession = Depends(get_db)):
    if not settings.ALLOW_REGISTRATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration is disabled.",
        )
    result = await db.execute(select(User).where(User.username == payload.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already taken.")
    user = User(
        username=payload.username,
        hashed_password=hash_password(payload.password),
        is_admin=False,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user
