import uuid
from datetime import datetime, timedelta, timezone

# Post-audit: solo PyJWT (python-jose rimosso: API rotta in 3.5 + CVE senza
# fix). I token legacy usano gli stessi claim standard HS256 (sub/role/exp/
# jti), quindi PyJWT li verifica senza fallback.
import jwt as pyjwt
from jwt import ExpiredSignatureError as PyJWTExpired, InvalidTokenError as PyJWTInvalid
_HAS_PYJWT = True

try:
    from pwdlib import PasswordHash
    _pwd = PasswordHash.recommended()
    _HAS_PWDLIB = True
except Exception:  # pragma: no cover
    _pwd = None
    _HAS_PWDLIB = False

from passlib.context import CryptContext
import redis.asyncio as redis
from app.core.config import settings

# Client Redis Asincrono
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)

# Password hashing context (fast Argon2id params for local deployment)
# Legacy context kept to VERIFY old hashes. New hashes use pwdlib.
_pwd_context = CryptContext(
    schemes=["argon2", "bcrypt"],
    deprecated="auto",
    argon2__time_cost=2,
    argon2__memory_cost=65536,
    argon2__parallelism=1,
)


def hash_password(password: str) -> str:
    if _HAS_PWDLIB:
        return _pwd.hash(password)
    return _pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if _HAS_PWDLIB:
        try:
            return _pwd.verify(plain_password, hashed_password)
        except Exception:
            pass  # fall through to legacy verify
    return _pwd_context.verify(plain_password, hashed_password)


def needs_rehash(hashed_password: str) -> bool:
    if _HAS_PWDLIB:
        try:
            # pwdlib >=0.2.x non espone check_needs_rehash su PasswordHash:
            # si confrontano i parametri argon2id dell'hash con quelli
            # dell'hasher recommended corrente (cache del probe).
            checker = getattr(_pwd, "check_needs_rehash", None)
            if callable(checker):
                return bool(checker(hashed_password))
            return _argon2_params_drifted(hashed_password)
        except Exception:
            return True
    return _pwd_context.needs_update(hashed_password)


def _parse_argon2_params(hashed: str) -> tuple | None:
    """(m, t, p) da hash $argon2id$v=..$m=..,t=..,p=..$..., None se non parsabile."""
    import re as _re
    if not isinstance(hashed, str) or not hashed.startswith("$argon2id$"):
        return None
    m = _re.search(r"m=(\d+),t=(\d+),p=(\d+)", hashed)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


_recommended_params: tuple | None | bool = False


def _argon2_params_drifted(hashed: str) -> bool:
    """True se l'hash non e' argon2id coi parametri recommended attuali
    (=> rehash per migrare formati legacy come i default passlib)."""
    global _recommended_params
    current = _parse_argon2_params(hashed)
    if current is None:
        return True
    if _recommended_params is False:
        try:
            probe = _pwd.hash("needs-rehash-probe")
            _recommended_params = _parse_argon2_params(probe)
        except Exception:
            return True
    if not _recommended_params:
        return True
    return current != _recommended_params


# JWT helpers — solo PyJWT.
# Audit: iss/aud vincolanti (niente riuso cross-service) + leeway 30s.
JWT_ISSUER = "aegis-brain"
JWT_AUDIENCE = "aegis-api"
JWT_LEEWAY_S = 30


def create_access_token(subject: str, role: str, expires_minutes: int | None = None) -> tuple[str, str, int]:
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes or settings.JWT_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(subject),
        "role": role,
        "exp": expire,
        "jti": jti,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    token = pyjwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token, jti, int(expire.timestamp())


def decode_access_token(token: str) -> dict | None:
    try:
        return pyjwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM],
            issuer=JWT_ISSUER, audience=JWT_AUDIENCE, leeway=JWT_LEEWAY_S,
        )
    except (PyJWTExpired, PyJWTInvalid):
        return None
    except Exception:
        return None


# Token blacklist (Redis ASYNC). Revocation is security-critical: if Redis is
# unavailable we fail closed instead of accepting a token that may have been
# revoked. Callers can surface the resulting 401/503 as a degraded auth state.
async def blacklist_token(jti: str, expires_at_ts: int) -> bool:
    """Revoca un token e conferma la persistenza.

    La revoca è fail-closed: se Redis non conferma la scrittura, il chiamante
    non deve dichiarare il logout completato.
    """
    now_ts = int(datetime.now(timezone.utc).timestamp())
    ttl = max(0, expires_at_ts - now_ts)
    if ttl <= 0:
        return True
    try:
        await redis_client.setex(f"bl:{jti}", ttl, "1")
        return True
    except Exception as exc:
        # Non esporre dettagli Redis al client, ma lasciare traccia operativa.
        import logging
        logging.getLogger(__name__).error("JWT blacklist persistence failed: %s", exc)
        return False


async def is_token_blacklisted(jti: str) -> bool:
    if not jti:
        return True
    try:
        return await redis_client.exists(f"bl:{jti}") == 1
    except Exception:
        return True


# Throttle anti brute-force per account (audit: il rate-limit IP e'
# aggirabile via X-Forwarded-For dietro proxy; questo conta i fallimenti
# per email e blocca l'account per 15 min dopo 10 tentativi. Fail-open se
# Redis e' giu' (disponibilita'), con log.
LOGIN_FAIL_MAX = 10
LOGIN_FAIL_WINDOW_S = 900


async def login_throttled(email: str) -> bool:
    try:
        n = await redis_client.get(f"rl:loginfail:{(email or '').lower().strip()}")
        return int(n or 0) >= LOGIN_FAIL_MAX
    except Exception:
        return False


async def record_login_failure(email: str) -> None:
    try:
        key = f"rl:loginfail:{(email or '').lower().strip()}"
        n = await redis_client.incr(key)
        if n == 1:
            await redis_client.expire(key, LOGIN_FAIL_WINDOW_S)
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning("login throttle unavailable: %s", exc)


async def clear_login_failures(email: str) -> None:
    try:
        await redis_client.delete(f"rl:loginfail:{(email or '').lower().strip()}")
    except Exception:
        pass
