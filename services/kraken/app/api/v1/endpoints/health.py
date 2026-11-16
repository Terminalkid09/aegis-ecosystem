from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db.session import get_db
from app.db.redis import get_redis
from app.services.docker_manager import docker_manager
from app.core.config import settings
import time

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_simple():
    """Quick liveness probe — used by Docker healthcheck."""
    return {"status": "ok", "app": settings.APP_NAME, "version": settings.APP_VERSION}


@router.get("/detailed")
async def health_detailed(db: AsyncSession = Depends(get_db)):
    """
    Full readiness probe.
    Checks PostgreSQL, Redis and Docker daemon.
    Returns degraded/unhealthy if any dependency is down.
    """
    checks = {}
    overall = "healthy"

    # ── PostgreSQL ────────────────────────────────────────────────────────────
    t0 = time.monotonic()
    try:
        await db.execute(text("SELECT 1"))
        checks["postgres"] = {
            "status": "ok",
            "latency_ms": round((time.monotonic() - t0) * 1000, 2),
        }
    except Exception as e:
        checks["postgres"] = {"status": "error", "detail": str(e)}
        overall = "unhealthy"

    # ── Redis ─────────────────────────────────────────────────────────────────
    t0 = time.monotonic()
    try:
        redis = await get_redis()
        if redis is None:
            raise RuntimeError("Redis client not initialised")
        pong = await redis.ping()
        if not pong:
            raise RuntimeError("Redis ping returned False")
        info = await redis.info("memory")
        checks["redis"] = {
            "status": "ok",
            "latency_ms": round((time.monotonic() - t0) * 1000, 2),
            "used_memory_human": info.get("used_memory_human", "?"),
        }
    except Exception as e:
        checks["redis"] = {"status": "error", "detail": str(e)}
        if overall == "healthy":
            overall = "unhealthy"

    # ── Docker daemon ─────────────────────────────────────────────────────────
    t0 = time.monotonic()
    try:
        active = await docker_manager.list_active()
        checks["docker"] = {
            "status": "ok",
            "latency_ms": round((time.monotonic() - t0) * 1000, 2),
            "active_sandboxes": len(active),
        }
    except Exception as e:
        checks["docker"] = {"status": "degraded", "detail": str(e)}
        if overall == "healthy":
            overall = "degraded"

    status_code = 200 if overall == "healthy" else 503

    from fastapi.responses import JSONResponse
    return JSONResponse(
        content={
            "status": overall,
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "checks": checks,
        },
        status_code=status_code,
    )
