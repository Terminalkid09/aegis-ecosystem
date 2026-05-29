import uuid
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
from jose import jwt, JWTError
import redis.asyncio as redis
from app.core.config import settings

# Client Redis Asincrono
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)

# Password hashing context
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def needs_rehash(hashed_password: str) -> bool:
    return pwd_context.needs_update(hashed_password)


# JWT helpers
def create_access_token(subject: str, role: str, expires_minutes: int | None = None) -> tuple[str, str, int]:
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes or settings.JWT_EXPIRE_MINUTES)
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(subject),
        "role": role,
        "exp": expire,
        "jti": jti,
    }
    token = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return token, jti, int(expire.timestamp())


def decode_access_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except JWTError:
        return None


# Token blacklist (Redis ASYNC)
async def blacklist_token(jti: str, expires_at_ts: int):
    now_ts = int(datetime.now(timezone.utc).timestamp())
    ttl = max(0, expires_at_ts - now_ts)
    if ttl > 0:
        await redis_client.setex(f"bl:{jti}", ttl, "1")


async def is_token_blacklisted(jti: str) -> bool:
    return await redis_client.exists(f"bl:{jti}") == 1
