from fastapi import APIRouter
from app.api.v1 import auth, vault, osint, ai, telemetry, nodetrace, enroll, history, rules, discovery, ws

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth")
api_router.include_router(vault.router, prefix="/vault")
api_router.include_router(osint.router, prefix="/osint")
api_router.include_router(ai.router, prefix="/ai")
api_router.include_router(telemetry.router, prefix="/telemetry")
api_router.include_router(history.router, prefix="/telemetry")
api_router.include_router(enroll.router, prefix="/enroll")
api_router.include_router(rules.router, prefix="/rules")
api_router.include_router(discovery.router, prefix="/discovery")
api_router.include_router(ws.router, prefix="/ws")
api_router.include_router(nodetrace.router) # Root level compatibility routes
