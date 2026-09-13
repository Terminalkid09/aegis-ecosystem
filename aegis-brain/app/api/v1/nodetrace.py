from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
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
import secrets
import uuid
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
    processes: List[Dict[str, Any]] = Field(default_factory=list)
    disk_free: Optional[int] = None
    disk_total: Optional[int] = None
    network_sent: Optional[int] = None
    network_received: Optional[int] = None
    active_connections: Optional[int] = None
    users: List[Dict[str, Any]] = Field(default_factory=list)
    network_flows: List[Dict[str, Any]] = Field(default_factory=list)
    agent_version: Optional[str] = Field(None, max_length=50)
    capabilities: Optional[Any] = None
    anomalies: List[str] = Field(default_factory=list)

async def verify_nodetrace_agent(
    device_id: str,
    authorization: str = Header(..., alias="Authorization"),
    db: AsyncSession = Depends(get_db),
    request: Request = None,
    x_client_cert: str | None = Header(None, alias="X-Client-Cert"),
) -> Agent:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token format")

    try:
        agent_uuid = uuid.UUID(device_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid device_id format")

    result = await db.execute(select(Agent).where(Agent.agent_id == agent_uuid))
    agent = result.scalars().first()
    if not agent or not agent.device_token_hash:
        raise HTTPException(status_code=401, detail="Agent not registered")

    token = authorization[7:]
    if not verify_password(token, agent.device_token_hash):
        raise HTTPException(status_code=401, detail="Invalid agent token")

    # Post-audit gap-closing: le rotte legacy applicano lo stesso mTLS delle
    # rotte /telemetry (altrimenti required sarebbe aggirabile).
    from app.core.agent_deps import apply_agent_mtls
    apply_agent_mtls(agent, request, x_client_cert, bootstrap=False)

    return agent

@router.post("/register")
async def register_agent(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Static key (headless) OR single-use EnrollToken (one-liner) — same as /enroll.
    # Audit: compare_digest anti-timing (prima `==`).
    import hmac as _hmac
    _key = (payload.enroll_key or "").strip()
    _expected = (settings.AGENT_ENROLL_KEY or "").strip()
    valid_static = bool(_expected) and _hmac.compare_digest(_key, _expected)
    if not valid_static:
        import hashlib
        from datetime import datetime, timezone
        from app.database.models import EnrollToken
        digest = hashlib.sha256(payload.enroll_key.strip().encode()).hexdigest()
        r = await db.execute(select(EnrollToken).where(EnrollToken.token_hash == digest))
        tok = r.scalars().first()
        now = datetime.now(timezone.utc)
        if not (tok and not tok.revoked and not tok.used_at and tok.expires_at and tok.expires_at.replace(tzinfo=timezone.utc) > now):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid enrollment key")
        tok.used_at = now
        tok.used_by_hostname = payload.hostname[:255]

    # Check for existing agent
    result = await db.execute(select(Agent).where(Agent.hostname == payload.hostname, Agent.os_type == payload.os))
    existing = result.scalars().first()

    if existing:
        # Come /enroll: revocato = niente re-enroll autonomo (fail-closed).
        try:
            from app.services import pki as _pki
            import os as _os
            _rl = _pki.RevokeList(_os.path.join(settings.PKI_DIR, _pki.REVOKED))
            _rl.require_healthy()
            if _rl.agent_revoked(str(existing.agent_id)):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail="Agent revoked: contact SOC for re-admission")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=f"PKI unavailable: {e}")
        # Re-enroll: issue a fresh token so agent can authenticate again.
        # Audit: 192 bit (prima 64: nt-uuid16). Lunghezza opaca agli agenti.
        new_token = f"nt-{secrets.token_hex(24)}"
        existing.device_token_hash = hash_password(new_token)
        existing.last_seen = datetime.now(timezone.utc)
        await db.commit()

        # Update redis cache (best-effort; chiave = hash, mai secret in chiaro;
        # TTL anti-crescita: la cache ricade sul DB).
        try:
            import hashlib as _hashlib
            import redis.asyncio as aioredis
            rc = aioredis.from_url(settings.REDIS_URL)
            await rc.set(f"auth:agent:{_hashlib.sha256(new_token.encode()).hexdigest()}",
                         str(existing.agent_id), ex=86400)
        except Exception:
            pass

        return {
            "device_id": str(existing.agent_id),
            "device_token": new_token,
            "status": "re-enrolled"
        }

    agent_id = uuid.uuid4()
    token = f"nt-{secrets.token_hex(24)}"

    agent = Agent(
        agent_id=agent_id,
        hostname=payload.hostname,
        os_type=payload.os,
        agent_type="nodetrace",
        device_token_hash=hash_password(token)
    )
    db.add(agent)
    await db.commit()

    # Also cache for link-style auth if needed (best-effort; hash + TTL).
    try:
        import hashlib as _hashlib2
        import redis.asyncio as redis
        rc = redis.from_url(settings.REDIS_URL)
        await rc.set(f"auth:agent:{_hashlib2.sha256(token.encode()).hexdigest()}",
                     str(agent_id), ex=86400)
    except Exception:
        pass

    return {
        "device_id": str(agent_id),
        "device_token": token,
        "status": "registered"
    }

@router.post("/update")
async def update_telemetry(
    payload: TelemetryUpdate,
    db: AsyncSession = Depends(get_db),
    authorization: str = Header(..., alias="Authorization"),
    request: Request = None,
    x_client_cert: str | None = Header(None, alias="X-Client-Cert"),
):
    # Map NodeTrace payload to the universal EventSchema
    try:
        agent_id_uuid = uuid.UUID(payload.device_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid device_id format")

    await verify_nodetrace_agent(payload.device_id, authorization, db, request, x_client_cert)

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
        "agent_version": payload.agent_version,
        "capabilities": payload.capabilities,
        "anomalies": payload.anomalies,
    })
    await telemetry_service.process_telemetry(db, agent_id_uuid, data)
    return {"status": "ok"}

@router.post("/heartbeat")
async def heartbeat(
    payload: dict,
    db: AsyncSession = Depends(get_db),
    authorization: str = Header(..., alias="Authorization"),
    request: Request = None,
    x_client_cert: str | None = Header(None, alias="X-Client-Cert"),
):
    from app.database.models import DiscoveredHost
    agent_id_str = payload.get("device_id")
    if agent_id_str:
        try:
            await verify_nodetrace_agent(agent_id_str, authorization, db, request, x_client_cert)
            agent_id = uuid.UUID(agent_id_str)
            result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
            agent = result.scalars().first()
            if agent:
                agent.last_seen = datetime.now(timezone.utc)
                # Parity col main heartbeat: versione/capabilities + discovery sync.
                if isinstance(payload, dict):
                    if payload.get("agent_version"):
                        agent.agent_version = str(payload.get("agent_version"))[:50]
                    if isinstance(payload.get("capabilities"), (dict, list)):
                        agent.capabilities = payload.get("capabilities")
                if agent.ip_address:
                    hr = await db.execute(
                        select(DiscoveredHost).where(DiscoveredHost.ip_address == agent.ip_address)
                    )
                    host = hr.scalars().first()
                    if host:
                        host.nodetrace_status = "active"
                        host.last_seen = datetime.now(timezone.utc)
                await db.commit()
        except ValueError:
            pass
    return {"status": "ok"}

@router.get("/commands")
async def get_commands(
    device_id: str,
    db: AsyncSession = Depends(get_db),
    authorization: str = Header(..., alias="Authorization"),
    request: Request = None,
    x_client_cert: str | None = Header(None, alias="X-Client-Cert"),
):
    await verify_nodetrace_agent(device_id, authorization, db, request, x_client_cert)

    import redis.asyncio as redis
    rc = redis.from_url(settings.REDIS_URL, decode_responses=True)
    queue_name = f"aegis:commands:{device_id}"

    command = await rc.lpop(queue_name)
    if command:
        return json.loads(command)

    return None


@router.get("/commands/batch")
async def get_commands_batch(
    device_id: str,
    n: int = 50,
    db: AsyncSession = Depends(get_db),
    authorization: str = Header(..., alias="Authorization"),
    request: Request = None,
    x_client_cert: str | None = Header(None, alias="X-Client-Cert"),
):
    await verify_nodetrace_agent(device_id, authorization, db, request, x_client_cert)
    import redis.asyncio as redis
    rc = redis.from_url(settings.REDIS_URL, decode_responses=True)
    queue_name = f"aegis:commands:{device_id}"
    out = []
    try:
        for _ in range(max(1, min(n, 100))):
            raw = await rc.lpop(queue_name)
            if not raw:
                break
            try:
                out.append(json.loads(raw))
            except Exception:
                continue
    except Exception:
        pass
    return out
