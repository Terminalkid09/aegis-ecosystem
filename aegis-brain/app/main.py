from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import asyncio
import os
import uuid
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.core.config import settings
from app.core.logging import get_logger, set_request_id, get_request_id
from app.core.rate_limit import limiter
from app.database.connection import init_db
from app.api.v1.router import api_router
from app.core.health import readiness_check, startup_check, liveness_check
from app.core.circuit_breaker import get_breaker_status
from app.core.metrics import inc, observe_hist, render_prometheus, fmt_labels, normalize_path_label
from fastapi import Response as FastAPIResponse

from app.services.redis_consumer import RedisConsumer
from app.services.alert_enrichment import auto_enrich_new_alerts
from app.api.v1.auth import SESSION_COOKIE, SESSION_COOKIE_PATH
from app.core.security import create_access_token, decode_access_token, is_token_blacklisted
from datetime import datetime, timezone

logger = get_logger(__name__)
_consumer: RedisConsumer | None = None

async def _auto_enrich_loop():
    while True:
        try:
            await auto_enrich_new_alerts()
        except Exception as e:
            logger.error(f"Auto-enrichment loop error: {e}")
        await asyncio.sleep(15)

@asynccontextmanager
def enforce_enterprise_strict() -> None:
    """Guard production P2.7: deployment enterprise senza mTLS = rifiuto
    esplicito all'avvio, mai degrado silenzioso a off. Puro e testabile."""
    if settings.ENTERPRISE_STRICT:
        from app.services.mtls import mtls_mode
        if mtls_mode() != "required":
            raise RuntimeError(
                "ENTERPRISE_STRICT is true but MTLS_MODE != required: "
                "enable the mTLS overlay (docker-compose.mtls.yml) or "
                "disable ENTERPRISE_STRICT for lab/dev")


async def lifespan(app: FastAPI):
    global _consumer
    logger.info("Starting up Aegis-Brain...")
    enforce_enterprise_strict()
    try:
        # Run Alembic migrations asynchronously.
        # `cwd` è la cartella che contiene alembic.ini (in container: /app), non
        # un path assoluto hardcoded: senza questo il brain non parte fuori dal
        # container, e un'immagine con workdir diverso rompe all'avvio.
        import subprocess
        import sys
        from pathlib import Path
        project_dir = str(Path(__file__).resolve().parent.parent)
        try:
            result = await asyncio.to_thread(
                subprocess.run, ["alembic", "upgrade", "head"],
                capture_output=True, text=True, cwd=project_dir
            )
        except FileNotFoundError:
            # CLI `alembic` non nel PATH (venv minimale): stessa migrazione via modulo.
            result = await asyncio.to_thread(
                subprocess.run, [sys.executable, "-m", "alembic", "upgrade", "head"],
                capture_output=True, text=True, cwd=project_dir
            )
        if result.returncode != 0:
            logger.error(f"Alembic migration failed: {result.stderr or result.stdout}")
            raise RuntimeError("Database migration failed; refusing to start with an incomplete schema")
        logger.info("Alembic migrations applied successfully")
        
        await init_db()
        # Riconciliazione revoche (Fase 4): DB autorevole → file cache
        try:
            from app.services.pki import RevokeList, REVOKED
            from app.database.models import RevokedCert
            from app.database.connection import AsyncSessionLocal
            from sqlalchemy import select
            async with AsyncSessionLocal() as db:
                rows = (await db.execute(select(RevokedCert.agent_id))).scalars().all()
                db_entries = [f"agent:{r}" for r in rows]
                # Anche i serial se presenti (non usato ora, ma per completezza)
                rows2 = (await db.execute(select(RevokedCert.serial).where(RevokedCert.serial.is_not(None)))).scalars().all()
                db_entries += [s for s in rows2 if s]
                rl = RevokeList(os.path.join(settings.PKI_DIR, REVOKED))
                # Se file illeggibile o diverso, ricostruisci
                if set(db_entries) != rl.entries():
                    rl.rebuild_from_db(db_entries)
                    logger.info(f"Revoche riconciliate: {len(db_entries)} da DB → file")
        except Exception as e:
            logger.warning(f"Riconciliazione revoche fallita (fail-closed su verifica): {e}")
        _consumer = RedisConsumer()
        # Start as background async task
        asyncio.create_task(_consumer.start())
        asyncio.create_task(_auto_enrich_loop())
        # SIEM v4: partizioni mensili pronte prima che arrivi il primo evento,
        # poi listener syslog opzionale (default OFF).
        if settings.SIEM_ENABLED:
            try:
                from app.database.connection import AsyncSessionLocal
                from app.services.siem_store import ensure_monthly_partitions
                async with AsyncSessionLocal() as _db:
                    created = await ensure_monthly_partitions(_db)
                    await _db.commit()
                if created:
                    logger.info(f"Partizioni SIEM verificate/creare: {created}")
            except Exception as e:
                logger.warning(f"Partizioni SIEM non verificate: {e}")
            try:
                from app.services.syslog_server import start_syslog_listener
                await start_syslog_listener()
            except Exception as e:
                logger.warning(f"Listener syslog non avviato: {e}")
        # Retention schedulata (Fase 7): solo se abilitata, con audit e backup check
        try:
            if getattr(settings, "RETENTION_ENABLED", False):
                from app.services.retention import start_retention_task
                start_retention_task()
                logger.info("Retention scheduler avviato (dry-run=False, backup check attivo)")
        except Exception as e:
            logger.warning(f"Retention scheduler non avviato: {e}")
        logger.info("Database initialized, RedisConsumer and auto-enrichment started.")
        yield
    except Exception as e:
        logger.error(f"Error during startup: {e}")
        # Never serve an API with an unknown schema or missing security
        # dependencies. Container orchestration will restart/retry startup.
        raise
    finally:
        if _consumer:
            _consumer.stop()
        try:
            from app.services.syslog_server import stop_syslog_listener
            await stop_syslog_listener()
        except Exception:
            pass
        try:
            from app.services.retention import stop_retention_task
            stop_retention_task()
        except Exception:
            pass
        logger.info("Shutting down Aegis-Brain...")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Global 500 exception handler — prevents stack trace leaks
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    request_id = get_request_id() or "unknown"
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "request_id": request_id,
        },
    )

# Request ID middleware
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    import time as _time
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
    set_request_id(request_id)
    start = _time.perf_counter()
    response = await call_next(request)
    observe_hist("aegis_http_request_seconds", _time.perf_counter() - start)
    # Audit F3: path normalizzato (niente cardinalita' esplosa da UUID/ID),
    # valori escapati via fmt_labels.
    inc("aegis_http_requests_total", 1, fmt_labels(
        method=request.method,
        path=normalize_path_label(request.url.path),
        status=response.status_code,
    ))
    response.headers["X-Request-ID"] = request_id
    return response

# Body-size guard (Fase 2): payload troppo grandi sono rifiutati prima del
# parsing. Limiti differenziati per gli endpoint di ingestione.
BODY_LIMITS: dict[str, int] = {
    "/api/v1/telemetry/report": 10 * 1024 * 1024,
    "/api/v1/telemetry/report/batch": 20 * 1024 * 1024,
    "/api/v1/telemetry/heartbeat": 64 * 1024,
}
DEFAULT_BODY_LIMIT = 10 * 1024 * 1024


def _body_limit_for(path: str) -> int:
    """Limite byte per path. L'upload Total segue TOTAL_MAX_* (audit: prima
    il default 10MB uccideva file legittimi fino a 100MB)."""
    if path == "/api/v1/total/upload":
        try:
            from app.core.config import settings as _s
            return max(int(_s.TOTAL_MAX_FILE_MB), int(_s.TOTAL_MAX_ZIP_MB)) * 1024 * 1024
        except Exception:
            return DEFAULT_BODY_LIMIT
    return BODY_LIMITS.get(path, DEFAULT_BODY_LIMIT)


@app.middleware("http")
async def body_size_middleware(request: Request, call_next):
    limit = _body_limit_for(request.url.path)
    cl = request.headers.get("content-length")
    too_large = False
    if cl:
        try:
            if int(cl) > limit:
                inc("aegis_events_dropped_total", 1, 'reason="payload_too_large"')
                return JSONResponse(status_code=413, content={"detail": "Payload too large"})
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
    else:
        # Audit: senza content-length (chunked) il vecchio check non vedeva
        # nulla. Si contano i byte reali durante la lettura.
        received = 0
        too_large = False

        async def counting_receive():
            nonlocal received, too_large
            message = await request._receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    too_large = True
            return message

        request._receive = counting_receive  # type: ignore[attr-defined]
    response = await call_next(request)
    if cl is None and too_large:
        inc("aegis_events_dropped_total", 1, 'reason="payload_too_large"')
        return JSONResponse(status_code=413, content={"detail": "Payload too large"})
    return response

# Health check endpoints
@app.get("/health/live")
async def liveness():
    # Contratto (audit F4): {status: "alive", service, uptime_s}.
    # Solo prova di vita del processo: niente DB/rete/check.
    # Per lo stato funzionale usare /health/ready.
    return await liveness_check()

@app.get("/health/ready")
async def readiness():
    return await readiness_check()

@app.get("/health/startup")
async def startup():
    return await startup_check()

@app.get("/health/circuit-breakers")
async def circuit_breakers():
    return get_breaker_status()

@app.get("/metrics")
async def metrics():
    """Prometheus text exposition. Nessun dato sensibile: solo contatori e
    istogrammi aggregati per conteggio (mai per host in chiaro oltre i label già sanitizzati)."""
    return FastAPIResponse(content=render_prometheus(), media_type="text/plain; version=0.0.4")

# Security headers middleware
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/"):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none';"
    return response

@app.middleware("http")
async def sliding_session_middleware(request: Request, call_next):
    """Rinnova il cookie di sessione finche' l'utente lavora.

    Il JWT dura JWT_EXPIRE_MINUTES e non c'era alcun rinnovo: un analista con la
    dashboard aperta veniva riportato al login a meta' turno, e il sintomo
    riportato era "ricarico la pagina e mi richiede l'accesso". Quando il token
    ha consumato piu' di meta' della sua vita la risposta ne emette uno nuovo,
    quindi la sessione scivola in avanti con l'attivita' e scade davvero solo
    dopo un periodo di inattivita' pari alla TTL.

    Fail-soft per costruzione: qualunque problema qui non deve rompere una
    risposta che l'endpoint ha gia' prodotto. Il refresh avviene solo su una
    risposta riuscita e con un token non revocato, altrimenti si prolungherebbe
    una sessione che il SOC ha gia' chiuso.
    """
    response = await call_next(request)
    try:
        if response.status_code >= 400 or not request.url.path.startswith("/api/"):
            return response
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            return response
        payload = decode_access_token(token)
        if not payload:
            return response
        exp = payload.get("exp")
        if not exp:
            return response
        ttl_s = max(int(settings.JWT_EXPIRE_MINUTES), 1) * 60
        if int(exp) - int(datetime.now(timezone.utc).timestamp()) > ttl_s // 2:
            return response
        jti = payload.get("jti")
        if jti and await is_token_blacklisted(jti):
            return response
        fresh, _, _ = create_access_token(
            subject=str(payload.get("sub")), role=str(payload.get("role") or "user"))
        response.set_cookie(
            key=SESSION_COOKIE,
            value=fresh,
            httponly=True,
            samesite="strict",
            secure=settings.COOKIE_SECURE,
            max_age=ttl_s,
            path=SESSION_COOKIE_PATH,
        )
    except Exception as exc:  # mai un 500 per il rinnovo
        logger.warning(f"session refresh skipped: {exc}")
    return response


# CORS
allowed_origins = [origin.strip().rstrip("/") for origin in settings.ALLOWED_ORIGINS.split(",") if origin.strip()]
if "*" in allowed_origins and not settings.DEBUG:
    raise RuntimeError("Wildcard CORS is not allowed with credentials in production")

# Cookie-authenticated mutating requests must come from an explicitly allowed
# browser origin. Bearer-authenticated agents are not subject to this check.
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _origin_allowed(origin: str) -> bool:
    """Confronto origin tolerant ma sicuro (audit: localhost vs 127.0.0.1
    sono lo stesso host ma stringhe diverse -> 403 spuri in locale).
    Match esatto, oppure stesso (scheme, porta) con entrambi gli host loopback.
    """
    o = (origin or "").rstrip("/")
    if o in allowed_origins:
        return True
    try:
        from urllib.parse import urlparse
        po = urlparse(o if "://" in o else "http://" + o)
        for allowed in allowed_origins:
            pa = urlparse(allowed)
            if not pa.hostname:
                continue
            if (po.scheme or "http") != (pa.scheme or "http"):
                continue
            if (po.port or 80) != (pa.port or 80):
                continue
            if po.hostname == pa.hostname:
                return True
            if po.hostname in _LOOPBACK_HOSTS and pa.hostname in _LOOPBACK_HOSTS:
                return True
    except Exception:
        pass
    return False


@app.middleware("http")
async def csrf_origin_middleware(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.cookies.get("aegis_token"):
        origin = request.headers.get("origin", "").rstrip("/")
        if not _origin_allowed(origin):
            return JSONResponse(status_code=403, content={"detail": "Invalid request origin"})
    return await call_next(request)

# In production, ensure ALLOWED_ORIGINS is set to specific domains, not "*"
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)

# API V1 Router
app.include_router(api_router, prefix="/api/v1")

@app.get("/")
async def root():
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION
    }
