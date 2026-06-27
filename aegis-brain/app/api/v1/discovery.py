import asyncio
import ipaddress
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.database.connection import get_db
from app.database.models import Agent, DiscoveredHost, IPReputation


router = APIRouter(tags=["Aegis Discovery"])

DEFAULT_SCAN_PORTS = [22, 80, 135, 139, 443, 445, 3389, 8000, 8080]


def _host_out(host: DiscoveredHost) -> Dict[str, Any]:
    return {
        "id": host.id,
        "ip_address": host.ip_address,
        "hostname": host.hostname,
        "os_guess": host.os_guess,
        "status": host.status,
        "open_ports": host.open_ports or [],
        "agent_status": host.agent_status,
        "source": host.source,
        "first_seen": host.first_seen,
        "last_seen": host.last_seen,
        "notes": host.notes,
    }


def _reputation_out(rec: IPReputation) -> Dict[str, Any]:
    return {
        "id": rec.id,
        "ip_address": rec.ip_address,
        "label": rec.label,
        "confidence": rec.confidence,
        "source": rec.source,
        "details": rec.details,
        "updated_at": rec.updated_at,
    }


class DiscoveryScanRequest(BaseModel):
    cidr: str = Field(..., examples=["192.168.1.0/24"])
    ports: List[int] = Field(default_factory=lambda: DEFAULT_SCAN_PORTS)
    timeout_ms: int = Field(default=250, ge=50, le=2000)
    include_unreachable: bool = False


class ReputationUpsert(BaseModel):
    ip_address: str
    label: str = Field(..., pattern="^(known|suspicious|malicious|unknown)$")
    confidence: int = Field(default=50, ge=0, le=100)
    source: str = "manual"
    details: Optional[Dict[str, Any]] = None


class DeploymentPlanRequest(BaseModel):
    ip_address: str
    os_type: str = Field(default="linux", pattern="^(linux|windows)$")
    agent_type: str = Field(default="nodetrace", pattern="^(nodetrace|aegis-guard)$")
    method: str = Field(default="manual", pattern="^(manual|ssh|winrm)$")


async def _check_port(ip: str, port: int, timeout: float) -> Optional[int]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port
    except Exception:
        return None


def _guess_os(open_ports: List[int]) -> str:
    if 3389 in open_ports or 445 in open_ports or 135 in open_ports:
        return "windows"
    if 22 in open_ports:
        return "linux"
    if open_ports:
        return "network-service"
    return "unknown"


def _safe_network(cidr: str):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR: {exc}") from exc
    if network.num_addresses > 256:
        raise HTTPException(status_code=400, detail="Discovery scan is limited to 256 addresses")
    if not (network.is_private or network.is_loopback):
        raise HTTPException(status_code=400, detail="Discovery scan is limited to private or loopback networks")
    return network


async def _upsert_host(db: AsyncSession, ip: str, open_ports: List[int], source: str = "scan") -> DiscoveredHost:
    result = await db.execute(select(DiscoveredHost).where(DiscoveredHost.ip_address == ip))
    host = result.scalars().first()
    status_value = "reachable" if open_ports else "unreachable"
    hostname = None
    if open_ports:
        try:
            hostname = await asyncio.to_thread(socket.gethostbyaddr, ip)
            hostname = hostname[0]
        except Exception:
            hostname = None
    if host:
        host.hostname = hostname or host.hostname
        host.os_guess = _guess_os(open_ports)
        host.status = status_value
        host.open_ports = open_ports
        host.source = source
        host.last_seen = datetime.now(timezone.utc)
    else:
        host = DiscoveredHost(
            ip_address=ip,
            hostname=hostname,
            os_guess=_guess_os(open_ports),
            status=status_value,
            open_ports=open_ports,
            source=source,
        )
        db.add(host)
    return host


@router.post("/scan")
async def scan_network(payload: DiscoveryScanRequest, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    network = _safe_network(payload.cidr)
    ports = [p for p in payload.ports if 1 <= p <= 65535][:32]
    timeout = payload.timeout_ms / 1000
    discovered = []

    for addr in network.hosts() if network.num_addresses > 2 else network:
        ip = str(addr)
        checks = await asyncio.gather(*[_check_port(ip, port, timeout) for port in ports])
        open_ports = sorted([port for port in checks if port is not None])
        if open_ports or payload.include_unreachable:
            host = await _upsert_host(db, ip, open_ports)
            discovered.append(host)

    await db.commit()
    return {
        "cidr": str(network),
        "scanned_hosts": network.num_addresses,
        "discovered": [_host_out(h) for h in discovered],
    }


@router.get("/hosts")
async def list_hosts(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    result = await db.execute(select(DiscoveredHost).order_by(DiscoveredHost.last_seen.desc()).limit(250))
    return {"items": [_host_out(item) for item in result.scalars().all()]}


@router.post("/reputation")
async def upsert_reputation(payload: ReputationUpsert, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    try:
        ipaddress.ip_address(payload.ip_address)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IP address") from exc
    result = await db.execute(select(IPReputation).where(IPReputation.ip_address == payload.ip_address))
    rec = result.scalars().first()
    if rec:
        rec.label = payload.label
        rec.confidence = payload.confidence
        rec.source = payload.source
        rec.details = payload.details
        rec.updated_at = datetime.now(timezone.utc)
    else:
        rec = IPReputation(**payload.model_dump())
        db.add(rec)
    await db.commit()
    await db.refresh(rec)
    return _reputation_out(rec)


@router.get("/reputation")
async def list_reputation(db: AsyncSession = Depends(get_db), user=Depends(get_current_user), label: Optional[str] = Query(None)):
    stmt = select(IPReputation).order_by(IPReputation.updated_at.desc())
    if label:
        stmt = stmt.where(IPReputation.label == label)
    result = await db.execute(stmt.limit(250))
    return {"items": [_reputation_out(item) for item in result.scalars().all()]}


@router.post("/demo/start")
async def start_demo(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    demo_hosts = [
        {"ip": "10.10.10.21", "hostname": "demo-win-endpoint", "os": "windows", "type": "aegis-guard", "ports": [135, 445, 3389]},
        {"ip": "10.10.10.42", "hostname": "demo-linux-sensor", "os": "linux", "type": "nodetrace", "ports": [22, 8000]},
    ]
    agents = []
    for item in demo_hosts:
        agent_id = uuid.uuid5(uuid.NAMESPACE_DNS, f"aegis-demo:{item['hostname']}")
        result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
        agent = result.scalars().first()
        if not agent:
            agent = Agent(
                agent_id=agent_id,
                hostname=item["hostname"],
                ip_address=item["ip"],
                os_type=item["os"],
                agent_type=item["type"],
                meta={"demo": True},
                last_seen=now,
            )
            db.add(agent)
        else:
            agent.last_seen = now
            agent.ip_address = item["ip"]
        host = await _upsert_host(db, item["ip"], item["ports"], source="demo")
        host.hostname = item["hostname"]
        host.agent_status = "demo-online"
        agents.append(agent)

    await db.commit()
    return {"status": "demo_started", "agents": [{"agent_id": str(a.agent_id), "hostname": a.hostname} for a in agents]}


@router.post("/demo/heartbeat")
async def demo_heartbeat(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    result = await db.execute(select(Agent))
    agents = [agent for agent in result.scalars().all() if isinstance(agent.meta, dict) and agent.meta.get("demo") is True]
    for agent in agents:
        agent.last_seen = now
    await db.commit()
    return {"status": "heartbeat_refreshed", "count": len(agents)}


@router.post("/deployment/plan")
async def deployment_plan(payload: DeploymentPlanRequest, user=Depends(get_current_user)):
    try:
        ipaddress.ip_address(payload.ip_address)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid IP address") from exc

    if payload.agent_type == "nodetrace":
        local_command = "cd NodeTrace\\agents\\python && python agent.py"
        remote_command = f"python NodeTrace/agents/python/agent.py  # run on {payload.ip_address}"
    else:
        local_command = "cd aegis-guard && java -jar target\\aegis-guard.jar"
        remote_command = f"java -jar aegis-guard.jar  # run on {payload.ip_address}"

    return {
        "status": "planned",
        "method": payload.method,
        "ip_address": payload.ip_address,
        "agent_type": payload.agent_type,
        "local_command": local_command,
        "remote_command": remote_command,
        "note": "Remote SSH/WinRM execution is intentionally not automatic. Use this plan after confirming host credentials and authorization.",
    }
