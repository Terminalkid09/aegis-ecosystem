from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database.connection import get_db
from app.database.models import User
from app.core.security import hash_password, verify_password, needs_rehash, create_access_token, decode_access_token, blacklist_token
from app.api.schemas.common import TokenResponse, UserOut
from app.core.rate_limit import limiter
from app.core.deps import get_current_user
from app.core.config import settings
from pydantic import BaseModel, Field
from typing import Optional

router = APIRouter(tags=["Authentication"])

USERNAME_RE = r"^[A-Za-z0-9._-]{3,150}$"


class UserCreate(BaseModel):
    # Audit: validazione identità (niente stringhe vuote/giganti/XSS-stored).
    username: str = Field(..., min_length=3, max_length=150, pattern=USERNAME_RE)
    email: str = Field(..., min_length=5, max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    password: str = Field(..., min_length=8, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)

SESSION_COOKIE = "aegis_token"
SESSION_COOKIE_PATH = "/api/"


def _set_auth_cookie(response: Response, token: str):
    """Set JWT as httpOnly, Secure (in production), SameSite=Strict cookie.

    `max_age` is derived from JWT_EXPIRE_MINUTES and not hardcoded: it used to
    be a literal 3600 next to a configurable TTL, so changing the setting left
    the browser dropping the cookie after an hour anyway.
    """
    # A cookie left by an older build on a different path (/) would be sent
    # *alongside* the current one, and the server reads the last value for a
    # repeated name: with a stale duplicate every request answered 401 until
    # the browser state was cleared by hand. Expire it on every login.
    response.delete_cookie(key=SESSION_COOKIE, path="/", httponly=True,
                           samesite="strict", secure=settings.COOKIE_SECURE)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="strict",
        secure=settings.COOKIE_SECURE,
        max_age=settings.JWT_EXPIRE_MINUTES * 60,
        path=SESSION_COOKIE_PATH,
    )

@router.post("/register", response_model=TokenResponse)
@limiter.limit("5/minute")
async def register(request: Request, payload: UserCreate, response: Response, db: AsyncSession = Depends(get_db)):
    # Audit: in enterprise (ALLOW_OPEN_REGISTRATION=false) solo admin crea utenti.
    if not settings.ALLOW_OPEN_REGISTRATION:
        from app.core.deps import get_optional_user
        admin = await get_optional_user(
            authorization=request.headers.get("Authorization"),
            request=request, db=db)
        if not admin or (admin.role or "").lower() != "admin":
            raise HTTPException(status_code=403, detail="Open registration disabled")
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password)
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    
    token, jti, exp = create_access_token(subject=str(user.id), role=user.role)
    _set_auth_cookie(response, token)
    return {"access_token": token, "token_type": "bearer", "user": user}

@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(request: Request, payload: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    from app.core.security import login_throttled, record_login_failure, clear_login_failures
    if await login_throttled(payload.email):
        raise HTTPException(status_code=429, detail="Too many failed attempts, try later")
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalars().first()

    if not user or not verify_password(payload.password, user.password_hash):
        await record_login_failure(payload.email)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Account disattivato: non autentica, nemmeno con credenziali corrette.
    if not user.active:
        raise HTTPException(status_code=403, detail="Account disabled")

    await clear_login_failures(payload.email)
    
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
        await db.commit()
        
    token, jti, exp = create_access_token(subject=str(user.id), role=user.role)
    _set_auth_cookie(response, token)
    return {"access_token": token, "token_type": "bearer", "user": user}

@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Blacklist the current JWT and clear the auth cookie."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if token:
        payload = decode_access_token(token)
        if payload:
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                if not await blacklist_token(jti, int(exp)):
                    raise HTTPException(
                        status_code=503,
                        detail="Token revocation service unavailable",
                    )
    # Both paths: the current one and the legacy one a duplicate could live on.
    for path in (SESSION_COOKIE_PATH, "/"):
        response.delete_cookie(
            key=SESSION_COOKIE,
            path=path,
            httponly=True,
            samesite="strict",
            secure=settings.COOKIE_SECURE,
        )
    return {"status": "logged_out", "detail": "Token blacklisted and cookie cleared."}

@router.get("/me")
@limiter.limit("30/minute")
async def get_me(request: Request, user: User = Depends(get_current_user)):
    """Return current user info. Used by frontend to check auth state on reload."""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
    }
