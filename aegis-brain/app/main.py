from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
from app.core.config import settings
from app.core.logging import get_logger
from app.database.connection import init_db
from app.api.v1.router import api_router

from app.services.redis_consumer import RedisConsumer

logger = get_logger(__name__)
_consumer: RedisConsumer | None = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _consumer
    logger.info("Starting up Aegis-Brain...")
    try:
        await init_db()
        _consumer = RedisConsumer()
        # Start as background async task
        asyncio.create_task(_consumer.start())
        logger.info("Database initialized and Async RedisConsumer started.")
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

# CORS
allowed_origins = settings.ALLOWED_ORIGINS.split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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
