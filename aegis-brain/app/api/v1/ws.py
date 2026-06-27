import asyncio
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select

from app.core.security import decode_access_token, is_token_blacklisted
from app.database.connection import AsyncSessionLocal
from app.database.models import Agent, Alert


router = APIRouter(tags=["Live Updates"])


async def _overview_snapshot():
    async with AsyncSessionLocal() as db:
        unresolved = (await db.execute(select(func.count(Alert.id)).where(Alert.is_resolved == False))).scalar() or 0
        critical = (await db.execute(select(func.count(Alert.id)).where(Alert.is_resolved == False, func.upper(Alert.severity) == "CRITICAL"))).scalar() or 0
        threshold = datetime.now(timezone.utc) - timedelta(minutes=15)
        active_agents = (await db.execute(select(func.count(Agent.agent_id)).where(Agent.last_seen >= threshold))).scalar() or 0
        return {
            "type": "overview",
            "active_agents": active_agents,
            "unresolved_alerts": unresolved,
            "current_critical_alerts": critical,
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }


async def _accept_token(token: str | None) -> bool:
    if not token:
        return False
    payload = decode_access_token(token)
    if not payload:
        return False
    jti = payload.get("jti")
    if jti and await is_token_blacklisted(jti):
        return False
    return True


@router.websocket("/overview")
async def overview_socket(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not await _accept_token(token):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    try:
        while True:
            await websocket.send_json(await _overview_snapshot())
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        return
