import asyncio
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy import func, select, or_

from app.core.security import decode_access_token, is_token_blacklisted
from app.database.connection import AsyncSessionLocal
from app.database.models import Agent, Alert


router = APIRouter(tags=["Live Updates"])


async def _overview_snapshot():
    async with AsyncSessionLocal() as db:
        not_resolved = or_(Alert.is_resolved == False, Alert.is_resolved == None)
        unresolved = (await db.execute(select(func.count(Alert.id)).where(not_resolved))).scalar() or 0
        critical = (await db.execute(select(func.count(Alert.id)).where(not_resolved, func.upper(Alert.severity) == "CRITICAL"))).scalar() or 0
        high = (await db.execute(select(func.count(Alert.id)).where(not_resolved, func.upper(Alert.severity) == "HIGH"))).scalar() or 0
        medium = (await db.execute(select(func.count(Alert.id)).where(not_resolved, func.upper(Alert.severity) == "MEDIUM"))).scalar() or 0
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
    if not jti or await is_token_blacklisted(jti):
        return False
    return True


@router.websocket("/overview")
async def overview_socket(websocket: WebSocket):
    # Never accept bearer tokens in the URL: URLs are commonly logged by
    # reverse proxies and browsers. The dashboard uses the HttpOnly cookie.
    token = websocket.cookies.get("aegis_token")
    if not await _accept_token(token):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    try:
        while True:
            snapshot = await _overview_snapshot()
            snapshot["t"] = datetime.now(timezone.utc).isoformat()
            await websocket.send_json(snapshot)

            # Wait for 30s, or handle ping from client
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if msg == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                # Timeout is expected every 30s, loop continues to send the next snapshot
                pass
    except WebSocketDisconnect:
        return


@router.websocket("/alerts")
async def alerts_socket(websocket: WebSocket):
    """Push realtime degli alert nuovi (bus in-process).

    Autenticazione identica all'overview: cookie HttpOnly, mai token nell'URL.
    Il client riceve {'type':'alert', ...} appena l'alert nasce; un client
    lento non blocca gli altri (queue per-client, piena = skip per quel client).
    """
    token = websocket.cookies.get("aegis_token")
    if not await _accept_token(token):
        await websocket.close(code=1008)
        return

    from app.services import alert_bus
    queue = alert_bus.subscribe()
    await websocket.accept()
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=25.0)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                # keepalive: il client sa che il canale e' vivo
                await websocket.send_text("ping")
    except WebSocketDisconnect:
        return
    except Exception:
        return
    finally:
        alert_bus.unsubscribe(queue)
