from typing import Optional
import redis.asyncio as aioredis
from app.core.config import settings
from loguru import logger

redis_client: Optional[aioredis.Redis] = None

TOKEN_BLACKLIST_PREFIX = "kraken:bl:"  # TTL = max token lifetime
REFRESH_USED_PREFIX = "kraken:rt:"  # single-use refresh token rotation


async def get_redis() -> Optional[aioredis.Redis]:
    return redis_client


async def init_redis():
    global redis_client
    redis_client = await aioredis.from_url(
        settings.REDIS_URL,
        encoding="utf-8",
        decode_responses=True,
        socket_connect_timeout=5,
        socket_timeout=5,
    )
    await redis_client.ping()
    logger.info("✅ Redis connected.")


async def close_redis():
    global redis_client
    if redis_client:
        await redis_client.aclose()
        logger.info("Redis connection closed.")


# ── Token Blacklist ───────────────────────────────────────────────────────────


async def blacklist_token(jti: str, ttl_seconds: int) -> None:
    """Add token ID to blacklist with TTL equal to token lifetime."""
    r = await get_redis()
    if r is None:
        logger.warning("Redis unavailable — token blacklist skipped")
        return
    key = f"{TOKEN_BLACKLIST_PREFIX}{jti}"
    await r.set(key, "1", ex=ttl_seconds)


async def is_token_blacklisted(jti: str) -> bool:
    r = await get_redis()
    if r is None:
        logger.warning("Redis unavailable — rejecting request (fail-closed)")
        return True
    key = f"{TOKEN_BLACKLIST_PREFIX}{jti}"
    return await r.exists(key) == 1


async def consume_refresh_jti(jti: str, ttl_seconds: int) -> bool:
    """Atomically consume a refresh token jti; False also means Redis is down."""
    r = await get_redis()
    if r is None:
        logger.warning("Redis unavailable — refusing refresh (fail-closed)")
        return False
    key = f"{REFRESH_USED_PREFIX}{jti}"
    try:
        if await r.exists(f"{TOKEN_BLACKLIST_PREFIX}{jti}"):
            return False
        result = await r.set(key, "1", ex=max(ttl_seconds, 1), nx=True)
        return bool(result)
    except Exception as e:
        logger.error(f"Refresh-token rotation failed: {e}")
        return False
