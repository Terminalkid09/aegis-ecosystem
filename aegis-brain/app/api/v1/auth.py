from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete as sa_delete, or_
from app.database.connection import get_db
from app.database.models import User, RememberDevice
from app.core.security import hash_password, verify_password, needs_rehash, create_access_token, decode_access_token, blacklist_token
from app.api.schemas.common import TokenResponse, UserOut
from app.core.rate_limit import limiter
from app.core.deps import get_current_user
from app.core.config import settings
from pydantic import BaseModel, Field
from typing import Optional
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

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
    remember: bool = False  # "Mantieni l'accesso su questo dispositivo"

SESSION_COOKIE = "aegis_token"
SESSION_COOKIE_PATH = "/api/"
REMEMBER_COOKIE = "aegis_remember"
# Path ristretto alle rotte di auth: il remember cookie NON viaggia verso gli
# endpoint dati (e comunque non sarebbe un JWT, quindi inerte).
REMEMBER_COOKIE_PATH = "/api/v1/auth"
REMEMBER_DAYS = 30
MAX_DEVICES_PER_USER = 10


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
    if payload.remember:
        await _issue_remember_device(request, response, db, user)
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
    # "Mantieni l'accesso": il logout da una macchina (specie condivisa) deve
    # finire ANCHE il trust del dispositivo, altrimenti il prossimo visitatore
    # del browser rientra senza credenziali.
    raw = request.cookies.get(REMEMBER_COOKIE)
    if raw:
        res = await db.execute(
            select(RememberDevice).where(RememberDevice.token_hash == _remember_hash(raw)))
        device = res.scalars().first()
        if device and not device.revoked:
            device.revoked = True
            await db.commit()
    response.delete_cookie(
        key=REMEMBER_COOKIE, path=REMEMBER_COOKIE_PATH, httponly=True,
        samesite="strict", secure=settings.COOKIE_SECURE)
    return {"status": "logged_out", "detail": "Token blacklisted and cookie cleared."}

@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("30/minute")
async def refresh_session(request: Request, response: Response, user: User = Depends(get_current_user)):
    """Rinnova la sessione: nuovo token + nuovo cookie.

    Esiste perche' una sessione che scade a metà lavoro costringeva al
    re-login con perdita dello stato della pagina. Il client la chiama in
    silenzio a meta' della finestra di validita' (e al ritorno sulla
    finestra): l'utente non vede mai la scadenza. Un account disattivato
    viene gia' rifiutato da get_current_user.
    """
    token, jti, exp = create_access_token(subject=str(user.id), role=user.role)
    _set_auth_cookie(response, token)
    return {"access_token": token, "token_type": "bearer", "user": user}


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


# ---------------------------------------------------------------------------
# Remember-me: "Mantieni l'accesso su questo dispositivo"
#
# Modello GitHub/Google: cookie separato (path ristretto alle rotte di auth)
# che contiene SOLO un token opaco; sul server c'e' solo lo sha256, quindi un
# dump del DB non permette di impersonare il dispositivo. Ogni uso RUOTA il
# token (il vecchio muore): un cookie rubato funziona una volta sola. I dispositivi sono elencati e revocabili dall'utente.
# ---------------------------------------------------------------------------


def _remember_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _guess_device_label(user_agent: str) -> str:
    ua = user_agent or ""
    browser = ("Edge" if "Edg/" in ua else
               "Opera" if "OPR/" in ua else
               "Chrome" if "Chrome/" in ua else
               "Firefox" if "Firefox/" in ua else
               "Safari" if "Safari/" in ua else "Browser")
    os_name = ("Windows" if "Windows" in ua else
               "macOS" if "Mac OS" in ua or "Macintosh" in ua else
               "Linux" if "Linux" in ua else
               "Android" if "Android" in ua else
               "iOS" if "iPhone" in ua or "iPad" in ua else "OS sconosciuto")
    return f"{browser} · {os_name}"


async def _prune_remember_devices(db: AsyncSession, user_id: int) -> None:
    """Pulisce i dispositivi morti e tiene un tetto per utente (MAX_DEVICES)."""
    now = datetime.now(timezone.utc)
    await db.execute(sa_delete(RememberDevice).where(
        RememberDevice.user_id == user_id,
        or_(RememberDevice.revoked.is_(True), RememberDevice.expires_at < now)))
    res = await db.execute(
        select(RememberDevice)
        .where(RememberDevice.user_id == user_id)
        .order_by(RememberDevice.created_at.desc()))
    devices = res.scalars().all()
    for stale in devices[MAX_DEVICES_PER_USER - 1:]:
        stale.revoked = True


async def _issue_remember_device(
        request: Request, response: Response, db: AsyncSession, user: User) -> None:
    """Crea il dispositivo fidato e mette il cookie (SOLO il token in chiaro)."""
    raw = secrets.token_urlsafe(48)
    now = datetime.now(timezone.utc)
    await _prune_remember_devices(db, user.id)
    ua = (request.headers.get("user-agent") or "")[:255]
    db.add(RememberDevice(
        user_id=user.id,
        token_hash=_remember_hash(raw),
        device_label=_guess_device_label(ua),
        user_agent=ua,
        last_used_at=now,
        expires_at=now + timedelta(days=REMEMBER_DAYS),
    ))
    await db.commit()
    response.set_cookie(
        key=REMEMBER_COOKIE,
        value=raw,
        httponly=True,
        samesite="strict",
        secure=settings.COOKIE_SECURE,
        max_age=REMEMBER_DAYS * 86400,
        path=REMEMBER_COOKIE_PATH,
    )


def _clear_remember_cookie(response: Response) -> None:
    response.delete_cookie(
        key=REMEMBER_COOKIE, path=REMEMBER_COOKIE_PATH, httponly=True,
        samesite="strict", secure=settings.COOKIE_SECURE)


@router.post("/remember", response_model=TokenResponse)
@limiter.limit("10/minute")
async def remember_login(
        request: Request, response: Response,
        db: AsyncSession = Depends(get_db)):
    """Login silenzioso da dispositivo fidato: scambio il remember-token.

    Chiamato dal frontend quando la sessione e' scaduta ma esiste il cookie
    remember: se valido, l'utente rientra senza ridigitare le credenziali.
    Il token consumato viene revocato e ne nasce uno nuovo (rotazione): un
    cookie rubato funziona una volta sola.
    """
    raw = request.cookies.get(REMEMBER_COOKIE)
    if not raw:
        raise HTTPException(status_code=401, detail="No remember token")
    now = datetime.now(timezone.utc)
    res = await db.execute(
        select(RememberDevice).where(RememberDevice.token_hash == _remember_hash(raw)))
    device = res.scalars().first()
    if not device or device.revoked or device.expires_at < now:
        # Token scaduto/revocato/sconosciuto: il cookie non vale piu', va via.
        _clear_remember_cookie(response)
        raise HTTPException(status_code=401, detail="Remember token invalid or expired")
    ures = await db.execute(select(User).where(User.id == device.user_id))
    user = ures.scalars().first()
    if not user or not user.active:
        _clear_remember_cookie(response)
        raise HTTPException(status_code=401, detail="Account disabled")

    device.last_used_at = now
    device.revoked = True  # rotazione: il nuovo token e' nell'_issue sotto
    await db.commit()

    token, jti, exp = create_access_token(subject=str(user.id), role=user.role)
    _set_auth_cookie(response, token)
    await _issue_remember_device(request, response, db, user)
    return {"access_token": token, "token_type": "bearer", "user": user}


@router.get("/devices")
@limiter.limit("30/minute")
async def list_remember_devices(
        request: Request,
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)):
    """Dispositivi con 'Mantieni l'accesso' attivo per l'utente corrente."""
    now = datetime.now(timezone.utc)
    res = await db.execute(
        select(RememberDevice)
        .where(RememberDevice.user_id == user.id)
        .order_by(RememberDevice.created_at.desc()))
    devices = res.scalars().all()
    return [
        {
            "id": d.id,
            "device_label": d.device_label,
            "user_agent": d.user_agent,
            "created_at": d.created_at,
            "last_used_at": d.last_used_at,
            "expires_at": d.expires_at,
            "revoked": bool(d.revoked) or d.expires_at < now,
        }
        for d in devices
    ]


@router.delete("/devices/{device_id}")
async def revoke_remember_device(
        device_id: int,
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db)):
    """Revoca un dispositivo: al prossimo uso il cookie remember muore."""
    res = await db.execute(select(RememberDevice).where(
        RememberDevice.id == device_id, RememberDevice.user_id == user.id))
    device = res.scalars().first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    device.revoked = True
    await db.commit()
    return {"status": "revoked", "id": device_id}
