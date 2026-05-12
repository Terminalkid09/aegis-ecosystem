import threading
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.endpoints import router
from database.connection import init_db
from services.redis_consumer import RedisConsumer
from utils.logger import get_logger

logger = get_logger(__name__)
_consumer: RedisConsumer | None = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _consumer
    try:
        init_db()
        _consumer = RedisConsumer()
        # Avvio del consumer in un thread separato con gestione errori
        consumer_thread = threading.Thread(target=_consumer.start, daemon=True)
        consumer_thread.start()
        logger.info("RedisConsumer thread started successfully.")
        yield
    except Exception as e:
        logger.error(f"Error during startup: {e}")
        yield
    finally:
        if _consumer:
            _consumer.stop()
            logger.info("RedisConsumer stopped.")

app = FastAPI(title="Aegis-Brain", lifespan=lifespan)
# CORS — Configurato per il frontend React (porta 3000)
allowed_origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router, prefix="/api/v1")

@app.get("/")
async def root():
    return {"status": "ok", "service": "aegis-brain"}
