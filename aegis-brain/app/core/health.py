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
    # Ollama e' un assistente opzionale: la sua indisponibilita' deve essere
    # visibile, ma non puo' rendere non pronto il core EDR/XDR.
    # Stesso principio per gli altri nomi in OPTIONAL_CHECKS (grafana,
    # prometheus, osint): se registrati e non sani, degradano invece di
    # rendere il servizio not-ready. Nomi non registrati sono ignorati.
    OPTIONAL_CHECKS = {"ollama", "grafana", "prometheus", "osint"}

    def __init__(self):
        self._checks = {}
        self._register_default_checks()

    def _register_default_checks(self):
        self.register("database", self._check_database)
        self.register("redis", self._check_redis)
        self.register("ollama", self._check_ollama)
        self.register("pipeline", self._check_pipeline)
        self.register("pki", self._check_pki)
        self.register("mtls", self._check_mtls)

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

    async def _check_pipeline(self) -> HealthCheckResult:
        """Salute della pipeline eventi: duplicati scartati e gap di sequenza
        misurati non sono un'anomalia di per sé, ma segnalano consegna incerta."""
        from app.services import event_dedup
        details = {
            "duplicates": getattr(event_dedup, "DEDUP", None) and event_dedup.DEDUP.duplicates,
            "seq_gaps": getattr(event_dedup, "SEQ", None) and event_dedup.SEQ.gaps,
        }
        try:
            client = redis.from_url(get_redis_url(), socket_connect_timeout=2, socket_timeout=2)
            pending = await client.llen("aegis:events:pending")
            await client.aclose()
            details["queue_depth"] = pending
        except Exception:
            details["queue_depth"] = None
        status = HealthStatus.HEALTHY
        if (details["seq_gaps"] or 0) > 0:
            status = HealthStatus.DEGRADED
        return HealthCheckResult("pipeline", status, 0, details)

    async def _check_pki(self) -> HealthCheckResult:
        """PKI operativa: la revoke list file cache è leggibile e non vuota
        (o la directory PKI esiste). Fail-closed se illeggibile."""
        try:
            import os
            from app.services.pki import RevokeList, REVOKED
            rl = RevokeList(os.path.join(settings.PKI_DIR, REVOKED))
            entries = rl.entries() if hasattr(rl, "entries") else []
            return HealthCheckResult("pki", HealthStatus.HEALTHY, 0, {"revoked_count": len(entries)})
        except Exception as e:
            return HealthCheckResult("pki", HealthStatus.UNHEALTHY, 0, {}, str(e))

    async def _check_mtls(self) -> HealthCheckResult:
        try:
            from app.services.mtls import mtls_mode
            mode = mtls_mode()
            status = HealthStatus.HEALTHY
            if getattr(settings, "ENTERPRISE_STRICT", False) and mode != "required":
                status = HealthStatus.UNHEALTHY
                return HealthCheckResult("mtls", status, 0, {"mode": mode}, "ENTERPRISE_STRICT richiede MTLS_MODE=required")
            return HealthCheckResult("mtls", status, 0, {"mode": mode})
        except Exception as e:
            return HealthCheckResult("mtls", HealthStatus.DEGRADED, 0, {}, str(e))

    def get_overall_status(self, results: Dict[str, HealthCheckResult]) -> HealthStatus:
        critical = {
            name: result for name, result in results.items()
            if name not in self.OPTIONAL_CHECKS
        }
        if any(r.status == HealthStatus.UNHEALTHY for r in critical.values()):
            return HealthStatus.UNHEALTHY
        # Un optional unhealthy è comunque un segnale operativo da mostrare,
        # ma resta una degradazione e non un outage del servizio principale.
        if any(r.status in {HealthStatus.DEGRADED, HealthStatus.UNHEALTHY}
               for r in results.values()):
            return HealthStatus.DEGRADED
        return HealthStatus.HEALTHY

health_checker = HealthChecker()

_START_MONO = time.monotonic()


async def liveness_check() -> Dict[str, Any]:
    """Liveness = il processo e' vivo. SOLO questo: niente DB, niente rete,
    niente check (audit F4). Se questo endpoint risponde, il processo e'
    vivo per definizione; la salute funzionale e' compito di readiness."""
    return {
        "status": "alive",
        "service": "aegis-brain",
        "version": settings.APP_VERSION,
        "uptime_s": round(time.monotonic() - _START_MONO, 1),
    }

async def readiness_check() -> Dict[str, Any]:
    results = await health_checker.run_all()
    overall = health_checker.get_overall_status(results)
    if overall == HealthStatus.UNHEALTHY:
        return {"status": "not_ready", "checks": {k: {"status": v.status.value, "error": v.error} for k, v in results.items()}}
    return {"status": "ready", "checks": {k: {"status": v.status.value} for k, v in results.items()}}

async def startup_check() -> Dict[str, Any]:
    return await readiness_check()
