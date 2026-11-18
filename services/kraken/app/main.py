from fastapi import FastAPI, Request, HTTPException, status, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager
from loguru import logger

from app.core.config import settings
from app.core.limiter import limiter
from app.core.security import decode_access_token
from app.core.metrics import MetricsMiddleware, metrics_endpoint
from app.api.v1.router import api_router, tags_metadata
from app.db.session import init_db
from app.db.redis import init_redis, close_redis
from app.services.plugin_manager import plugin_manager
from app.services.retention import prune_malware
from app.services.outbox import start_outbox_worker, stop_outbox_worker
from app.core.event_bus import event_bus


async def verify_web_session(request: Request):
    token = request.cookies.get("kraken_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    request.state.user = payload


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Kraken starting up...")
    settings.validate_secrets()
    settings.ensure_dirs()
    prune_malware(
        settings.MALWARE_DIR,
        settings.MALWARE_RETENTION_DAYS,
        settings.MALWARE_MAX_TOTAL_BYTES,
    )
    await init_db()
    await init_redis()
    await plugin_manager.initialize()
    await event_bus.emit_async("system.startup")
    start_outbox_worker()
    logger.info("All systems ready.")
    yield
    await stop_outbox_worker()
    await plugin_manager.shutdown()
    await event_bus.emit_async("system.shutdown")
    await close_redis()
    logger.info("Kraken shut down cleanly.")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="""
**Kraken Honeypot & Threat Intelligence Platform**

A production-ready honeypot system with interactive sandbox analysis, real-time attack detection, and threat intelligence.

## Features

- **Multi-protocol honeypots**: SSH, Telnet, HTTP, FTP sensors
- **Interactive sandboxes**: Ephemeral containers for safe attack replay
- **Real-time dashboard**: Live attack visualization with geo-location
- **Malware capture**: Automatic extraction and SHA256 hashing
- **Export & Reporting**: CSV, JSON, PDF reports with rate limiting
- **JWT Authentication**: HttpOnly cookies with server-side validation
- **Prometheus Metrics**: Full observability stack with Grafana dashboards
- **Alerting**: Alertmanager with email, Slack, PagerDuty integrations

## Authentication

All API endpoints (except `/health`, `/login`, `/register`) require a valid JWT token.
Tokens can be provided via:
- `Authorization: Bearer <token>` header
- `kraken_token` HttpOnly cookie (set on login)

## Rate Limiting

- Login: 10 requests/minute
- Sensor ingestion: 200 requests/minute
- Export endpoints: 30 requests/minute
- Default: 60 requests/minute

## Sandbox Security

Sandboxes run with:
- Non-root user (`sandbox`)
- Read-only filesystem
- No network access (`network_mode: none`)
- Resource limits: 128MB RAM, 64 pids, 25% CPU
- No new privileges, all capabilities dropped
""",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    openapi_tags=tags_metadata,
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

app.add_middleware(MetricsMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "PUT"],
    allow_headers=["Authorization", "Content-Type"],
)

# ── Security Headers middleware ────────────────────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store"
    return response

# ── Body size limit — reject payloads > MAX_BODY_SIZE ─────────────────────────
@app.middleware("http")
async def limit_body_size(request: Request, call_next):
    max_body = settings.MAX_BODY_SIZE
    content_length = request.headers.get("content-length")
    transfer_encoding = request.headers.get("transfer-encoding", "")
    if "chunked" in transfer_encoding.lower():
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Transfer-Encoding not supported."}, status_code=413)
    if content_length and int(content_length) > max_body:
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Request body too large."}, status_code=413)
    return await call_next(request)

# ── Static & templates ────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def _page(name: str, request: Request):
    # Starlette's current signature is (request, name, context); the old
    # (name, context) form broke every HTML route on this dependency version.
    return templates.TemplateResponse(
        request, name, {"public_base_path": settings.base_path()})

# ── API routes ────────────────────────────────────────────────────────────────
app.include_router(api_router)

# ── Metrics endpoint ──────────────────────────────────────────────────────────
@app.get("/metrics", include_in_schema=False)
async def metrics():
    return await metrics_endpoint()

# ── Dashboard HTML routes ─────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def dashboard(request: Request, _=Depends(verify_web_session)):
    return _page("dashboard.html", request)

@app.get("/login", include_in_schema=False)
async def login_page(request: Request):
    return _page("login.html", request)

@app.get("/sso", include_in_schema=False)
async def sso_page(request: Request):
    """Browser landing page for the Brain assertion (token stays in the hash)."""
    return _page("sso.html", request)

@app.get("/events", include_in_schema=False)
async def events_page(request: Request, _=Depends(verify_web_session)):
    return _page("events.html", request)

@app.get("/plugins", include_in_schema=False)
async def plugins_page(request: Request, _=Depends(verify_web_session)):
    return _page("plugins.html", request)

@app.get("/reports", include_in_schema=False)
async def reports_page(request: Request, _=Depends(verify_web_session)):
    return _page("reports.html", request)

@app.get("/operations", include_in_schema=False)
async def operations_page(request: Request, _=Depends(verify_web_session)):
    return _page("operations.html", request)

# Health endpoints are served via /api/v1/health (router)
