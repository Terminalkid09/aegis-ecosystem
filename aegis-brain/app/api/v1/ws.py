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
        high = (await db.execute(select(func.count(Alert.id)).where(Alert.is_resolved == False, func.upper(Alert.severity) == "HIGH"))).scalar() or 0
        medium = (await db.execute(select(func.count(Alert.id)).where(Alert.is_resolved == False, func.upper(Alert.severity) == "MEDIUM"))).scalar() or 0
        threshold = datetime.now(timezone.utc) - timedelta(minutes=15)
        active_agents = (await db.execute(select(func.count(Agent.agent_id)).where(Agent.last_seen >= threshold, Agent.is_demo == False))).scalar() or 0
        demo_agents = (await db.execute(select(func.count(Agent.agent_id)).where(Agent.last_seen >= threshold, Agent.is_demo == True))).scalar() or 0
        total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
        return {
            "type": "overview",
            "active_agents": active_agents,
            "demo_agents": demo_agents,
            "total_alerts": total_alerts,
            "unresolved_alerts": unresolved,
            "current_critical_alerts": critical,
            "current_high_alerts": high,
            "current_medium_alerts": medium,
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
            snapshot = await _overview_snapshot()
            snapshot["t"] = datetime.now(timezone.utc).isoformat()
            await websocket.send_json(snapshot)
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        return
