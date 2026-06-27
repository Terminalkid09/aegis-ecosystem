import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any, Optional
import redis.asyncio as redis
import asyncpg
import httpx
from app.core.config import settings
from app.core.logging import get_logger
from app.core.redis_utils import get_redis_url

logger = get_logger(__name__)

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"

@dataclass
class HealthCheckResult:
    name: str
    status: HealthStatus
    latency_ms: float
    details: Dict[str, Any]
    error: Optional[str] = None

class HealthChecker:
    def __init__(self):
        self._checks = {}
        self._register_default_checks()

    def _register_default_checks(self):
        self.register("database", self._check_database)
        self.register("redis", self._check_redis)
        self.register("ollama", self._check_ollama)

    def register(self, name: str, check_func):
        self._checks[name] = check_func

    async def run_all(self) -> Dict[str, HealthCheckResult]:
        results = {}
        for name, check_func in self._checks.items():
            start = time.perf_counter()
            try:
                result = await check_func()
                latency = (time.perf_counter() - start) * 1000
                if isinstance(result, HealthCheckResult):
                    result.latency_ms = latency
                    results[name] = result
                else:
                    results[name] = HealthCheckResult(
                        name=name,
                        status=HealthStatus.HEALTHY if result else HealthStatus.UNHEALTHY,
                        latency_ms=latency,
                        details={}
                    )
            except Exception as e:
                latency = (time.perf_counter() - start) * 1000
                logger.error(f"Health check {name} failed", extra={"error": str(e)})
                results[name] = HealthCheckResult(
                    name=name,
                    status=HealthStatus.UNHEALTHY,
                    latency_ms=latency,
                    details={},
                    error=str(e)
                )
        return results

    async def _check_database(self) -> HealthCheckResult:
        try:
            conn = await asyncpg.connect(settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://"))
            await conn.execute("SELECT 1")
            await conn.close()
            return HealthCheckResult("database", HealthStatus.HEALTHY, 0, {"driver": "asyncpg"})
        except Exception as e:
            return HealthCheckResult("database", HealthStatus.UNHEALTHY, 0, {}, str(e))

    async def _check_redis(self) -> HealthCheckResult:
        try:
            client = redis.from_url(get_redis_url(), socket_connect_timeout=2, socket_timeout=2)
            await client.ping()
            await client.aclose()
            return HealthCheckResult("redis", HealthStatus.HEALTHY, 0, {"mode": "standalone"})
        except Exception as e:
            return HealthCheckResult("redis", HealthStatus.UNHEALTHY, 0, {}, str(e))

    async def _check_ollama(self) -> HealthCheckResult:
        if not settings.OLLAMA_URL:
            return HealthCheckResult("ollama", HealthStatus.DEGRADED, 0, {}, "Not configured")
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{settings.OLLAMA_URL.replace('/api/generate', '')}/api/tags")
                if resp.status_code == 200:
                    models = resp.json().get("models", [])
                    return HealthCheckResult("ollama", HealthStatus.HEALTHY, 0, {"models_count": len(models)})
                return HealthCheckResult("ollama", HealthStatus.DEGRADED, 0, {"status_code": resp.status_code})
        except Exception as e:
            return HealthCheckResult("ollama", HealthStatus.UNHEALTHY, 0, {}, str(e))

    def get_overall_status(self, results: Dict[str, HealthCheckResult]) -> HealthStatus:
        if any(r.status == HealthStatus.UNHEALTHY for r in results.values()):
            return HealthStatus.UNHEALTHY
        if any(r.status == HealthStatus.DEGRADED for r in results.values()):
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY

health_checker = HealthChecker()

async def liveness_check() -> Dict[str, Any]:
    results = await health_checker.run_all()
    overall = health_checker.get_overall_status(results)
    return {
        "status": overall.value,
        "checks": {k: {"status": v.status.value, "latency_ms": v.latency_ms, "details": v.details, "error": v.error} for k, v in results.items()}
    }

async def readiness_check() -> Dict[str, Any]:
    results = await health_checker.run_all()
    overall = health_checker.get_overall_status(results)
    if overall == HealthStatus.UNHEALTHY:
        return {"status": "not_ready", "checks": {k: {"status": v.status.value, "error": v.error} for k, v in results.items()}}
    return {"status": "ready", "checks": {k: {"status": v.status.value} for k, v in results.items()}}

async def startup_check() -> Dict[str, Any]:
    return await readiness_check()