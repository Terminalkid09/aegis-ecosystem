from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import asyncio
import uuid
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.core.config import settings
from app.core.logging import get_logger, set_request_id, get_request_id
from app.core.rate_limit import limiter
from app.database.connection import init_db
from app.api.v1.router import api_router
from app.core.health import health_checker, liveness_check, readiness_check, startup_check
from app.core.circuit_breaker import get_breaker_status

from app.services.redis_consumer import RedisConsumer
from app.services.alert_enrichment import auto_enrich_new_alerts

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
async def lifespan(app: FastAPI):
    global _consumer
    logger.info("Starting up Aegis-Brain...")
    try:
        # Run Alembic migrations
        import subprocess
        result = subprocess.run(["alembic", "upgrade", "head"], capture_output=True, text=True, cwd="/app")
        if result.returncode != 0:
            logger.error(f"Alembic migration failed: {result.stderr or result.stdout}")
            raise RuntimeError("Database migration failed; refusing to start with an incomplete schema")
        logger.info("Alembic migrations applied successfully")
        
        await init_db()
        _consumer = RedisConsumer()
        # Start as background async task
        asyncio.create_task(_consumer.start())
        asyncio.create_task(_auto_enrich_loop())
        logger.info("Database initialized, RedisConsumer and auto-enrichment started.")
        yield
    except Exception as e:
        logger.error(f"Error during startup: {e}")
        yield
    finally:
        if _consumer:
            _consumer.stop()
        logger.info("Shutting down Aegis-Brain...")

app = FastAPI(
    title=settings.APP_NAME,
    version="2.0.0",
    lifespan=lifespan
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Request ID middleware
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4())[:8])
    set_request_id(request_id)
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response

# Health check endpoints
@app.get("/health/live")
async def liveness():
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

# CORS
allowed_origins = settings.ALLOWED_ORIGINS.split(",")
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
        "version": "2.0.0"
    }
