from urllib.parse import quote
from app.core.config import settings


def get_redis_url() -> str:
    redis_url = settings.REDIS_URL
    if settings.REDIS_PASSWORD and "redis://" in redis_url and "@" not in redis_url:
        encoded_password = quote(settings.REDIS_PASSWORD, safe='')
        redis_url = redis_url.replace("redis://", f"redis://:{encoded_password}@")
    return redis_url
