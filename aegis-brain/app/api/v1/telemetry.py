from fastapi import APIRouter, Depends, HTTPException, status, Query, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import List, Optional
from datetime import datetime, timezone, timedelta
from app.database.connection import get_db
from app.database.models import Alert, Agent, Telemetry
from app.core.deps import get_current_user
from app.core.agent_deps import get_current_agent
from app.api.schemas.common import AlertResponse, AgentResponse, StatsResponse, EventSchema
from app.services import telemetry_service
from pydantic import BaseModel

router = APIRouter(tags=["Telemetry"])

class ResolveRequest(BaseModel):
    resolved: bool = True

@router.get("/alerts", response_model=List[AlertResponse])
async def get_alerts(
    db: AsyncSession = Depends(get_db), 
    _user = Depends(get_current_user),
    severity: Optional[str] = None,
    is_resolved: Optional[bool] = None
):
    stmt = select(Alert)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if is_resolved is not None:
        stmt = stmt.where(Alert.is_resolved == is_resolved)
    
    stmt = stmt.order_by(Alert.timestamp.desc()).limit(100)
    result = await db.execute(stmt)
    return result.scalars().all()

@router.patch("/alerts/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(alert_id: int, body: ResolveRequest, db: AsyncSession = Depends(get_db), _user = Depends(get_current_user)):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    if not alert.is_resolved and body.resolved:
        if alert.pid:
            await telemetry_service.send_command_to_agent(alert.agent_id, {
                "command": "KILL_PROCESS",
                "pid": alert.pid,
                "process_name": alert.process_name,
                "alert_id": alert.id
            })

    alert.is_resolved = body.resolved
    await db.commit()
    await db.refresh(alert)
    return alert

@router.get("/agents", response_model=List[AgentResponse])
async def get_agents(
    db: AsyncSession = Depends(get_db), 
    _user = Depends(get_current_user),
    active_only: bool = False,
    include_demo: bool = Query(False, description="Include demo agents"),
    limit: int = Query(100, ge=1, le=1000)
):
    stmt = select(Agent)
    if active_only:
        threshold = datetime.now(timezone.utc) - timedelta(minutes=15)
        stmt = stmt.where(Agent.last_seen >= threshold)
    if not include_demo:
        stmt = stmt.where(Agent.is_demo == False)

    stmt = stmt.order_by(Agent.last_seen.desc()).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()

@router.get("/recent")
async def get_recent_telemetry(
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user),
    agent_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200)
):
    stmt = (
        select(Telemetry, Agent)
        .join(Agent, Telemetry.device_id == Agent.agent_id)
        .filter(Agent.agent_type.in_(["nodetrace", "NodeTrace"])) # Robust multi-case check
    )
    if agent_id:
        stmt = stmt.where(Telemetry.device_id == agent_id)
    stmt = stmt.order_by(Telemetry.timestamp.desc()).limit(limit)
    result = await db.execute(stmt)
    return [
        {
            "id": telemetry.id,
            "agent_id": str(telemetry.device_id),
            "hostname": agent.hostname,
            "agent_type": agent.agent_type,
            "timestamp": telemetry.timestamp,
            "cpu_usage": telemetry.cpu_usage,
            "ram_usage": telemetry.ram_usage,
            "disk_free": telemetry.disk_free,
            "disk_total": telemetry.disk_total,
            "network_sent": telemetry.network_sent,
            "network_received": telemetry.network_received,
            "processes": telemetry.processes,
            "ip_local": telemetry.ip_local,
            "ip_public": telemetry.ip_public,
            "users": telemetry.users,
            "network_flows": telemetry.network_flows,
        }
        for telemetry, agent in result.all()
    ]

@router.get("/activity")
async def get_activity(
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user),
    limit: int = Query(30, ge=1, le=100)
):
    telemetry_result = await db.execute(
        select(Telemetry, Agent)
        .join(Agent, Telemetry.device_id == Agent.agent_id)
        .order_by(Telemetry.timestamp.desc())
        .limit(limit)
    )
    alert_result = await db.execute(
        select(Alert, Agent)
        .join(Agent, Alert.agent_id == Agent.agent_id)
        .order_by(Alert.timestamp.desc())
        .limit(limit)
    )

    activity = []
    for telemetry, agent in telemetry_result.all():
        activity.append({
            "type": "telemetry",
            "timestamp": telemetry.timestamp,
            "agent_id": str(telemetry.device_id),
            "hostname": agent.hostname,
            "summary": f"Telemetry OK: CPU {telemetry.cpu_usage or 0:.1f}% / RAM {telemetry.ram_usage or 0:.1f}%"
        })
    for alert, agent in alert_result.all():
        activity.append({
            "type": "alert",
            "timestamp": alert.timestamp,
            "agent_id": str(alert.agent_id),
            "hostname": agent.hostname,
            "severity": alert.severity,
            "summary": alert.description
        })

    return sorted(activity, key=lambda item: item["timestamp"], reverse=True)[:limit]

@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    db: AsyncSession = Depends(get_db), 
    _user = Depends(get_current_user),
    include_demo: bool = Query(False, description="Include demo agents in stats")
):
    total_alerts = (await db.execute(select(func.count(Alert.id)))).scalar() or 0
    unresolved = (await db.execute(select(func.count(Alert.id)).where(Alert.is_resolved == False))).scalar() or 0
    current_critical = (await db.execute(select(func.count(Alert.id)).where(Alert.is_resolved == False, func.upper(Alert.severity) == "CRITICAL"))).scalar() or 0
    current_high = (await db.execute(select(func.count(Alert.id)).where(Alert.is_resolved == False, func.upper(Alert.severity) == "HIGH"))).scalar() or 0
    current_medium = (await db.execute(select(func.count(Alert.id)).where(Alert.is_resolved == False, func.upper(Alert.severity) == "MEDIUM"))).scalar() or 0
    current_low = (await db.execute(select(func.count(Alert.id)).where(Alert.is_resolved == False, func.upper(Alert.severity) == "LOW"))).scalar() or 0
    
    threshold = datetime.now(timezone.utc) - timedelta(minutes=15)
    agent_query = select(func.count(Agent.agent_id)).where(Agent.last_seen >= threshold)
    if not include_demo:
        agent_query = agent_query.where(Agent.is_demo == False)
    active_agents = (await db.execute(agent_query)).scalar() or 0
    
    # Also count demo agents separately
    demo_agent_query = select(func.count(Agent.agent_id)).where(Agent.is_demo == True, Agent.last_seen >= threshold)
    demo_agents = (await db.execute(demo_agent_query)).scalar() or 0
    
    return StatsResponse(
        total_alerts=total_alerts,
        unresolved_alerts=unresolved,
        active_agents=active_agents,
        current_critical_alerts=current_critical,
        current_high_alerts=current_high,
        current_medium_alerts=current_medium,
        current_low_alerts=current_low,
        demo_agents=demo_agents
    )

@router.post("/report")
async def agent_report(payload: EventSchema, db: AsyncSession = Depends(get_db), agent: Agent = Depends(get_current_agent)):
    if str(agent.agent_id) != payload.agent_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent ID mismatch")
    await telemetry_service.process_telemetry(db, agent.agent_id, payload.model_dump())
    return {"status": "ok"}

@router.post("/heartbeat")
async def agent_heartbeat(data: dict, db: AsyncSession = Depends(get_db), agent: Agent = Depends(get_current_agent)):
    agent.last_seen = datetime.now(timezone.utc)
    await db.commit()
    return {"status": "ok"}

@router.get("/commands")
async def get_agent_commands(
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db)
):
    import redis.asyncio as redis
    from app.core.redis_utils import get_redis_url
    rc = redis.from_url(get_redis_url(), decode_responses=True)
    queue_name = f"aegis:commands:{agent.agent_id}"
    command = await rc.lpop(queue_name)
    if command:
        import json
        return json.loads(command)
    return None

@router.get("/remediations")
async def get_remediation_actions(limit: int = 20, db: AsyncSession = Depends(get_db)):
    from app.database.models import RemediationAction
    result = await db.execute(select(RemediationAction).order_by(RemediationAction.executed_at.desc()).limit(limit))
    actions = result.scalars().all()
    return [{"id": a.id, "alert_id": a.alert_id, "action": a.action, "target": a.target, "status": a.status, "executed_at": a.executed_at.isoformat() if a.executed_at else None, "details": a.details} for a in actions]

@router.get("/threat-reports")
async def get_threat_reports(limit: int = 50, db: AsyncSession = Depends(get_db), _user = Depends(get_current_user)):
    from app.database.models import ThreatReport
    result = await db.execute(select(ThreatReport).order_by(ThreatReport.created_at.desc()).limit(limit))
    reports = result.scalars().all()
    return [{"id": r.id, "alert_id": r.alert_id, "summary": r.summary, "confidence": r.confidence, "recommended_actions": r.recommended_actions, "osint_data": r.osint_data, "is_auto_generated": r.is_auto_generated, "created_at": r.created_at.isoformat() if r.created_at else None} for r in reports]
