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
            # pwdlib hashes start with $argon2 / $bcrypt — legacy passlib
            # hashes that fail the check need rehash to modern format.
            return _pwd.check_needs_rehash(hashed_password)
        except Exception:
            return True
    return _pwd_context.needs_update(hashed_password)


# JWT helpers — solo PyJWT.
def create_access_token(subject: str, role: str, expires_minutes: int | None = None) -> tuple[str, str, int]:
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes or settings.JWT_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(subject),
        "role": role,
        "exp": expire,
        "jti": jti,
    }
    token = pyjwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token, jti, int(expire.timestamp())


def decode_access_token(token: str) -> dict | None:
    try:
        return pyjwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    except (PyJWTExpired, PyJWTInvalid):
        return None
    except Exception:
        return None


# Token blacklist (Redis ASYNC). Revocation is security-critical: if Redis is
# unavailable we fail closed instead of accepting a token that may have been
# revoked. Callers can surface the resulting 401/503 as a degraded auth state.
async def blacklist_token(jti: str, expires_at_ts: int):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    ttl = max(0, expires_at_ts - now_ts)
    if ttl > 0:
        try:
            await redis_client.setex(f"bl:{jti}", ttl, "1")
        except Exception:
            pass


async def is_token_blacklisted(jti: str) -> bool:
    if not jti:
        return True
    try:
        return await redis_client.exists(f"bl:{jti}") == 1
    except Exception:
        return True
