from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete as sa_delete, or_
from app.database.connection import get_db
from app.database.models import User, RememberDevice, APIKey
from app.services.api_keys import generate_api_key, hash_api_key
from app.core.security import (
    hash_password, verify_password, verify_password_dummy, needs_rehash,
    create_access_token, decode_access_token, blacklist_token,
)
from app.api.schemas.common import TokenResponse, UserOut
from app.core.rate_limit import limiter
from app.core.deps import get_current_user
from app.core.config import settings
from app.core import oidc
from app.core.audit import log_audit
from pydantic import BaseModel, Field
from typing import Optional
from urllib.parse import quote
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


class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    source: Optional[str] = Field(None, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    scopes: list[str] = Field(default_factory=list, max_length=32)

SESSION_COOKIE = "aegis_token"
SESSION_COOKIE_PATH = "/api/"
OIDC_STATE_COOKIE = "aegis_oidc_state"
OIDC_STATE_COOKIE_PATH = "/api/v1/auth/oidc"
REMEMBER_COOKIE = "aegis_remember"
# Path ristretto alle rotte di auth: il remember cookie NON viaggia verso gli
# endpoint dati (e comunque non sarebbe un JWT, quindi inerte).
REMEMBER_COOKIE_PATH = "/api/v1/auth"
REMEMBER_DAYS = 30
MAX_DEVICES_PER_USER = 10


def _local_login_disabled() -> bool:
    """SSO-only mode is meaningful only when OIDC is actually enabled.

    A flag that hides the password form in the SPA but leaves the API open is
    not a security control. Enforce the same policy server-side here.
    """
    return bool(settings.OIDC_ENABLED and not settings.OIDC_ALLOW_LOCAL_LOGIN)


async def _safe_oidc_role(db: AsyncSession, user: User, desired_role: str) -> tuple[str, bool]:
    """Return the role to persist and whether a downgrade was suppressed.

    OIDC group sync must obey the same last-active-admin invariant as the
    Users API. Otherwise removing the only admin from the IdP group locks the
    deployment out on the next login.
    """
    if user.active and user.role == "admin" and desired_role != "admin":
        from app.core.deps import count_active_admins
        if await count_active_admins(db) <= 1:
            return "admin", True
    return desired_role, False


@router.get("/config")
async def auth_config():
    """Public login-page policy.

    The SPA must not offer a Register tab when self-service registration is
    disabled: the old UI always showed it and the only feedback was a 403
    after submitting. Expose the boolean only, never any secret.
    """
    return {"open_registration": bool(settings.ALLOW_OPEN_REGISTRATION)}


def _set_auth_cookie(response: Response, token: str):
    """Set JWT as httpOnly, Secure (in production), SameSite=Strict cookie.

    `max_age` is derived from JWT_EXPIRE_MINUTES and not hardcoded: it used to
    be a literal 3600 next to a configurable TTL, so changing the setting left
    the browser dropping the cookie after an hour anyway.
    """
    # Login/refresh responses carry a bearer token; never let a proxy or
    # browser cache store them.
    response.headers["Cache-Control"] = "no-store"
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
    if _local_login_disabled():
        raise HTTPException(status_code=403,
                            detail="Local account registration is disabled; use SSO")
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
    
    token, jti, exp = create_access_token(
        subject=str(user.id), role=user.role,
        token_version=getattr(user, "token_version", 0),
    )
    _set_auth_cookie(response, token)
    return {"access_token": token, "token_type": "bearer", "user": user}

@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
async def login(request: Request, payload: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    if _local_login_disabled():
        raise HTTPException(status_code=403,
                            detail="Local password login is disabled; use SSO")
    from app.core.security import login_throttled, record_login_failure, clear_login_failures
    if await login_throttled(payload.email):
        raise HTTPException(status_code=429, detail="Too many failed attempts, try later")
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalars().first()

    if not user:
        # Same Argon2 work and same response as a wrong password: no account
        # enumeration through status code or timing.
        verify_password_dummy(payload.password)
        await record_login_failure(payload.email)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user.password_hash):
        await record_login_failure(payload.email)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Disabled and wrong-password responses are intentionally identical.
    if not user.active:
        await record_login_failure(payload.email)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    await clear_login_failures(payload.email)
    
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
        await db.commit()
        
    token, jti, exp = create_access_token(
        subject=str(user.id), role=user.role,
        token_version=getattr(user, "token_version", 0),
    )
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
    token, jti, exp = create_access_token(
        subject=str(user.id), role=user.role,
        token_version=getattr(user, "token_version", 0),
    )
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
# OIDC umano (generic, provider-neutral)
# ---------------------------------------------------------------------------


def _clear_oidc_state(response: Response) -> None:
    response.delete_cookie(
        key=OIDC_STATE_COOKIE,
        path=OIDC_STATE_COOKIE_PATH,
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
    )


def _sso_error(message: str) -> RedirectResponse:
    """Return to the SPA without reflecting provider internals."""
    response = RedirectResponse(
        url=oidc.frontend_url(f"/?sso_error={quote(message)}"), status_code=302)
    _clear_oidc_state(response)
    return response


@router.get("/oidc/config")
async def oidc_config():
    """Public login policy: the SPA only renders SSO when it is configured."""
    return {
        "enabled": bool(settings.OIDC_ENABLED),
        "button_label": settings.OIDC_BUTTON_LABEL or "Sign in with SSO",
        "login_url": "/api/v1/auth/oidc/login",
        # If OIDC is off, local login is the only way in and must stay on.
        "local_login": bool(settings.OIDC_ALLOW_LOCAL_LOGIN or not settings.OIDC_ENABLED),
    }


@router.get("/oidc/login")
@limiter.limit("30/minute")
async def oidc_login(request: Request, return_to: str = "/"):
    if not settings.OIDC_ENABLED:
        raise HTTPException(status_code=404, detail="OIDC is not enabled")
    if not settings.JWT_SECRET:
        return _sso_error("SSO is not configured")

    try:
        metadata = await oidc.discover()
        verifier, challenge = oidc.pkce_pair()
        state = oidc.new_state()
        nonce = oidc.new_nonce()
        target = oidc.safe_return_to(return_to)
        url = oidc.authorization_url(
            metadata,
            state=state,
            nonce=nonce,
            challenge=challenge,
            redirect=oidc.redirect_uri(),
        )
    except oidc.OIDCError:
        return _sso_error("SSO provider unavailable")

    response = RedirectResponse(url=url, status_code=302)
    response.set_cookie(
        key=OIDC_STATE_COOKIE,
        value=oidc.encode_state(
            state=state, verifier=verifier, nonce=nonce, return_to=target),
        httponly=True,
        samesite="lax",
        secure=settings.COOKIE_SECURE,
        max_age=oidc.STATE_TTL_S,
        path=OIDC_STATE_COOKIE_PATH,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/oidc/callback")
@limiter.limit("30/minute")
async def oidc_callback(
    request: Request,
    db: AsyncSession = Depends(get_db),
    code: str | None = None,
    state: str | None = None,
):
    if not settings.OIDC_ENABLED:
        raise HTTPException(status_code=404, detail="OIDC is not enabled")

    try:
        state_payload = oidc.decode_state(request.cookies.get(OIDC_STATE_COOKIE))
        if not state or not secrets.compare_digest(str(state_payload.get("state", "")), state):
            raise oidc.OIDCError("state mismatch")
        if not code:
            raise oidc.OIDCError("missing authorization code")
        metadata = await oidc.discover()
        tokens = await oidc.exchange_code(
            metadata, code=code, verifier=str(state_payload["verifier"]),
            redirect=oidc.redirect_uri())
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise oidc.OIDCError("token response has no id_token")
        jwks = await oidc.fetch_jwks(metadata)
        claims = oidc.validate_id_token(
            id_token, jwks, nonce=str(state_payload.get("nonce") or ""))
        userinfo = await oidc.fetch_userinfo(
            metadata, str(tokens.get("access_token") or ""))
        if userinfo.get("sub") and userinfo.get("sub") != claims.get("sub"):
            raise oidc.OIDCError("userinfo subject mismatch")
        merged = {**claims, **userinfo}
        email = str(merged.get("email") or "").strip().lower()
        subject = str(claims.get("sub") or "").strip()
        if not email or not subject:
            raise oidc.OIDCError("provider did not return email/sub")
        if settings.OIDC_REQUIRE_VERIFIED_EMAIL and not oidc.email_verified(merged):
            raise oidc.OIDCError("email is not verified")
        groups = oidc.groups_from_claims(merged)
        role = oidc.role_from_groups(groups)
    except (oidc.OIDCError, ValueError, TypeError):
        return _sso_error("SSO authentication failed")

    issuer = oidc.issuer()
    result = await db.execute(select(User).where(
        User.oidc_issuer == issuer, User.oidc_subject == subject))
    user = result.scalars().first()
    linked_local = False
    role_sync_suppressed = False
    if not user and settings.OIDC_LINK_BY_EMAIL:
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalars().first()
        if user and user.oidc_subject not in (None, subject):
            return _sso_error("This account is linked to another identity")
        linked_local = bool(user)

    if user and not user.active:
        return _sso_error("Account disabled")

    if not user:
        if not settings.OIDC_AUTO_CREATE_USERS:
            return _sso_error("No account exists for this identity")
        base = oidc.username_from_claims(merged)
        username = base
        suffix = 1
        while (await db.execute(select(User).where(User.username == username))).scalars().first():
            suffix += 1
            username = f"{base[:140]}-{suffix}"
        user = User(
            username=username,
            email=email,
            password_hash=hash_password(secrets.token_urlsafe(48)),
            role=role,
            active=True,
            oidc_subject=subject,
            oidc_issuer=issuer,
        )
        db.add(user)
    else:
        if user.oidc_subject is None:
            user.oidc_subject = subject
            user.oidc_issuer = issuer
        elif user.oidc_subject == subject and settings.OIDC_SYNC_ROLE:
            role, role_sync_suppressed = await _safe_oidc_role(db, user, role)
            user.role = role
        # A local account linked by verified email keeps its existing role on
        # the link operation. Demoting a break-glass admin from an IdP group
        # mapping would lock the operator out of the local recovery path.
        if not linked_local and user.email != email:
            clash = (await db.execute(
                select(User).where(User.email == email, User.id != user.id)
            )).scalars().first()
            if not clash:
                user.email = email

    await db.commit()
    await db.refresh(user)
    await log_audit(
        db, action="login_oidc", resource="user", resource_id=str(user.id),
        user_id=user.id, username=user.username,
        details={"issuer": issuer, "email": email, "role": user.role,
                 "groups": groups[:50], "linked_local": linked_local,
                 "role_sync_suppressed": role_sync_suppressed},
        ip_address=request.client.host if request.client else None,
        user_agent=(request.headers.get("user-agent") or "")[:500],
    )
    await db.commit()

    token, _, _ = create_access_token(
        subject=str(user.id), role=user.role,
        token_version=getattr(user, "token_version", 0),
    )
    response = RedirectResponse(
        url=oidc.frontend_url(str(state_payload.get("return_to") or "/")),
        status_code=302)
    _set_auth_cookie(response, token)
    _clear_oidc_state(response)
    response.headers["Cache-Control"] = "no-store"
    return response


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

    token, jti, exp = create_access_token(
        subject=str(user.id), role=user.role,
        token_version=getattr(user, "token_version", 0),
    )
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


# ─── API key di ingestione (AEGIS-SEC-006) ─────────────────────────────────
# Amministrazione riservata all'admin: una chiave limitata a una sorgente non
# puo' essere creata da un analyst e usata per avvelenare un'altra sorgente.

def _require_key_admin(user: User) -> None:
    if (user.role or "").lower() != "admin":
        raise HTTPException(status_code=403, detail="API key management requires admin role")


def _key_out(key: APIKey) -> dict:
    scopes = key.scopes if isinstance(key.scopes, dict) else {}
    return {
        "id": key.id,
        "name": key.name,
        "source": key.source,
        "scopes": scopes.get("scopes", []),
        "active": bool(key.active) and key.revoked_at is None,
        "created_at": key.created_at.isoformat() if key.created_at else None,
        "revoked_at": key.revoked_at.isoformat() if key.revoked_at else None,
        "last_used": key.last_used.isoformat() if key.last_used else None,
    }


@router.get("/api-keys")
async def list_api_keys(user: User = Depends(get_current_user),
                       db: AsyncSession = Depends(get_db)):
    _require_key_admin(user)
    result = await db.execute(select(APIKey).order_by(APIKey.created_at.desc()))
    return [_key_out(k) for k in result.scalars().all()]


@router.post("/api-keys")
async def create_api_key(payload: APIKeyCreate,
                         user: User = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    _require_key_admin(user)
    raw = generate_api_key()
    key = APIKey(
        user_id=user.id,
        name=payload.name,
        hashed_key=hash_api_key(raw),
        source=payload.source,
        scopes={"scopes": payload.scopes},
        active=True,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return {**_key_out(key), "api_key": raw, "warning": "shown only once"}


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(key_id: int,
                         user: User = Depends(get_current_user),
                         db: AsyncSession = Depends(get_db)):
    _require_key_admin(user)
    key = await db.get(APIKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key.active = False
    key.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "revoked", "id": key_id}
