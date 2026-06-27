from fastapi import APIRouter, Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database.connection import get_db
from app.database.models import Agent
from app.core.security import hash_password
from app.core.security import verify_password
from app.core.config import settings
from app.services import telemetry_service
from app.api.schemas.common import EventSchema
from pydantic import BaseModel, Field
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

router = APIRouter(tags=["NodeTrace Compatibility"])

class RegisterRequest(BaseModel):
    hostname: str
    os: str
    enroll_key: str
    mac_address: Optional[str] = None

class TelemetryUpdate(BaseModel):
    device_id: str
    cpu_usage: float
    ram_usage: float
    ip_local: Optional[str] = None
    ip_public: Optional[str] = None
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    processes: List[str] = Field(default_factory=list)
    disk_free: Optional[int] = None
    disk_total: Optional[int] = None
    network_sent: Optional[int] = None
    network_received: Optional[int] = None
    active_connections: Optional[int] = None
    users: List[Dict[str, Any]] = Field(default_factory=list)
    network_flows: List[Dict[str, Any]] = Field(default_factory=list)

async def verify_nodetrace_agent(
    device_id: str,
    authorization: str = Header(..., alias="Authorization"),
    db: AsyncSession = Depends(get_db)
) -> Agent:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")

    try:
        agent_uuid = uuid.UUID(device_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid device_id format")

    result = await db.execute(select(Agent).where(Agent.agent_id == agent_uuid))
    agent = result.scalars().first()
    if not agent or not agent.device_token_hash:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Agent not registered")

    token = authorization[7:]
    if not verify_password(token, agent.device_token_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token")

    return agent

@router.post("/register")
async def register_agent(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    if payload.enroll_key != settings.AGENT_ENROLL_KEY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid enrollment key")

    # Check for existing agent
    result = await db.execute(select(Agent).where(Agent.hostname == payload.hostname, Agent.os_type == payload.os))
    existing = result.scalars().first()
    
    if existing:
        return {
            "device_id": str(existing.agent_id),
            "device_token": "ALREADY_REGISTERED",
            "status": "registered"
        }

    agent_id = uuid.uuid4()
    token = f"nt-{uuid.uuid4().hex[:16]}"
    
    agent = Agent(
        agent_id=agent_id,
        hostname=payload.hostname,
        os_type=payload.os,
        agent_type="nodetrace",
        device_token_hash=hash_password(token)
    )
    db.add(agent)
    await db.commit()
    
    # Also cache for link-style auth if needed
    import redis.asyncio as redis
    rc = redis.from_url(settings.REDIS_URL)
    await rc.set(f"auth:agent:{token}", str(agent_id))
    
    return {
        "device_id": str(agent_id),
        "device_token": token,
        "status": "registered"
    }

@router.post("/update")
async def update_telemetry(
    payload: TelemetryUpdate,
    db: AsyncSession = Depends(get_db),
    authorization: str = Header(..., alias="Authorization")
):
    # Map NodeTrace payload to the universal EventSchema
    try:
        agent_id_uuid = uuid.UUID(payload.device_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid device_id format")

    await verify_nodetrace_agent(payload.device_id, authorization, db)

    event = EventSchema(
        agent_id=payload.device_id,
        timestamp=datetime.now(timezone.utc),
        event_type="METRICS_REPORT",
        ip_address=payload.ip_local,
        cpu_usage=payload.cpu_usage,
        ram_usage=payload.ram_usage,
        disk_free=payload.disk_free,
        disk_total=payload.disk_total,
        network_sent=payload.network_sent,
        network_received=payload.network_received,
        processes=[{"name": p} for p in payload.processes],
        users=payload.users,
        network_flows=payload.network_flows
    )
    
    # Process through the standard telemetry service
    data = event.model_dump()
    data.update({
        "ip_local": payload.ip_local,
        "ip_public": payload.ip_public,
        "geo_country": payload.geo_country,
        "geo_city": payload.geo_city,
        "users": payload.users,
        "network_flows": payload.network_flows,
    })
    await telemetry_service.process_telemetry(db, agent_id_uuid, data)
    return {"status": "ok"}

@router.post("/heartbeat")
async def heartbeat(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    authorization: str = Header(..., alias="Authorization")
):
    agent_id_str = payload.get("device_id")
    if agent_id_str:
        try:
            await verify_nodetrace_agent(agent_id_str, authorization, db)
            agent_id = uuid.UUID(agent_id_str)
            result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
            agent = result.scalars().first()
            if agent:
                agent.last_seen = datetime.now(timezone.utc)
                await db.commit()
        except ValueError:
            pass
    return {"status": "ok"}

@router.get("/commands")
async def get_commands(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    authorization: str = Header(..., alias="Authorization")
):
    await verify_nodetrace_agent(device_id, authorization, db)
    
    import redis.asyncio as redis
    rc = redis.from_url(settings.REDIS_URL, decode_responses=True)
    queue_name = f"aegis:commands:{device_id}"
    
    command = await rc.lpop(queue_name)
    if command:
        return json.loads(command)
    
    return None
