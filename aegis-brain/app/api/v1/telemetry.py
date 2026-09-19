from fastapi import APIRouter, Depends, HTTPException, status, Query, Header, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_
from typing import Any, List, Optional
from datetime import datetime, timezone, timedelta
from app.database.connection import get_db
from app.database.models import Alert, Agent, Telemetry, ThreatReport, RemediationAction
from app.core.deps import get_current_user, require_perm, has_perm
from app.core.agent_deps import get_current_agent
from app.api.schemas.common import AlertResponse, AgentResponse, StatsResponse, EventSchema
from app.services import telemetry_service
from app.services import event_dedup
from app.core.audit import log_audit
from app.core.logging import get_logger
from app.core.metrics import inc, observe_hist, set_gauge
from app.core.rate_guard import ingest_rate_guard
from app.core.redaction import sanitize_event
from pydantic import BaseModel, Field, ValidationError

router = APIRouter(tags=["Telemetry"])
logger = get_logger(__name__)

class ResolveRequest(BaseModel):
    resolved: bool = True

@router.get("/alerts", response_model=List[AlertResponse])
async def get_alerts(
    db: AsyncSession = Depends(get_db), 
    _user = Depends(get_current_user),
    severity: Optional[str] = None,
    # Senza filtro si vedono TUTTI gli alert: nascondere i risolti per default
    # cancellava la storia del triage (audit UI: i resolved non apparivano mai).
    # `resolved` resta accettato come alias: era il nome che la UI inviava e
    # veniva silenziosamente ignorato.
    is_resolved: Optional[bool] = Query(None),
    resolved: Optional[bool] = Query(None, include_in_schema=False),
    skip: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=1000)
):
    stmt = select(Alert)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    effective_resolved = is_resolved if is_resolved is not None else resolved
    if effective_resolved is not None:
        if effective_resolved:
            stmt = stmt.where(Alert.is_resolved == True)
        else:
            stmt = stmt.where(or_(Alert.is_resolved == False, Alert.is_resolved == None))
    
    stmt = stmt.order_by(Alert.timestamp.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()

@router.get("/alerts/{alert_id}")
async def get_alert_detail(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user)
):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    agent = await db.get(Agent, alert.agent_id)
    
    threat_reports = []
    tr_result = await db.execute(
        select(ThreatReport).where(ThreatReport.alert_id == alert_id).order_by(ThreatReport.created_at.desc())
    )
    for tr in tr_result.scalars().all():
        threat_reports.append({
            "id": tr.id,
            "summary": tr.summary,
            "confidence": tr.confidence,
            "recommended_actions": tr.recommended_actions,
            "osint_data": tr.osint_data,
            "ai_analysis": tr.ai_analysis,
            "is_auto_generated": tr.is_auto_generated,
            "created_at": tr.created_at.isoformat() if tr.created_at else None,
        })
    
    remediations = []
    rem_result = await db.execute(
        select(RemediationAction).where(RemediationAction.alert_id == alert_id).order_by(RemediationAction.executed_at.desc())
    )
    for r in rem_result.scalars().all():
        remediations.append({
            "id": r.id,
            "action": r.action,
            "target": r.target,
            "status": r.status,
            "executed_at": r.executed_at.isoformat() if r.executed_at else None,
            "details": r.details,
        })
    
    telemetry_sample = None
    tel_result = await db.execute(
        select(Telemetry).where(Telemetry.device_id == alert.agent_id).order_by(Telemetry.timestamp.desc()).limit(1)
    )
    tel = tel_result.scalars().first()
    if tel:
        telemetry_sample = {
            "cpu_usage": tel.cpu_usage,
            "ram_usage": tel.ram_usage,
            "processes": tel.processes,
            "users": tel.users,
            "network_flows": tel.network_flows,
        }
    
    return {
        "id": alert.id,
        "agent_id": str(alert.agent_id),
        "agent_hostname": agent.hostname if agent else None,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        "severity": alert.severity,
        "pid": alert.pid,
        "process_name": alert.process_name,
        "process_path": alert.process_path,
        "event_type": alert.event_type,
        "description": alert.description,
        "is_resolved": alert.is_resolved,
        "telemetry": telemetry_sample,
        "threat_reports": threat_reports,
        "remediations": remediations,
    }

@router.post("/alerts/resolve-all")
async def resolve_all_alerts(
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user),
    request: Request = None,
):
    if (_user.role or "user").lower() not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Bulk resolve requires admin/analyst role")
    stmt = select(Alert).where(or_(Alert.is_resolved == False, Alert.is_resolved == None))
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    count = 0
    for alert in alerts:
        if not alert.is_resolved:
            alert.is_resolved = True
            count += 1
    await db.commit()
    await log_audit(
        db, action="resolve_all_alerts", resource="alert",
        details={"count": count}, user_id=_user.id, username=_user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()
    return {"resolved": count, "detail": f"Resolved {count} unresolved alerts"}

@router.delete("/alerts")
async def delete_all_alerts(
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user),
    request: Request = None,
):
    if (_user.role or "user").lower() != "admin":
        raise HTTPException(status_code=403, detail="Bulk delete requires admin role")
    stmt = select(Alert)
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    count = len(alerts)
    for alert in alerts:
        await db.delete(alert)
    await db.commit()
    await log_audit(
        db, action="delete_all_alerts", resource="alert",
        details={"count": count}, user_id=_user.id, username=_user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()
    return {"deleted": count, "detail": f"Deleted {count} alerts"}

@router.patch("/alerts/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(
    alert_id: int, body: ResolveRequest,
    db: AsyncSession = Depends(get_db),
    # Audit: triage per risolvere; KILL_PROCESS solo con "respond".
    # Prima bastava un login qualsiasi (viewer compreso).
    _user = Depends(require_perm("triage", "respond")),
    request: Request = None,
):
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    killed = False
    if not alert.is_resolved and body.resolved:
        safe_to_kill = alert.event_type in ("PROCESS_CREATED", "custom_rule")
        can_respond = has_perm(_user.role, "respond")
        if alert.pid and safe_to_kill and can_respond:
            try:
                await telemetry_service.send_command_to_agent(alert.agent_id, {
                    "command": "KILL_PROCESS",
                    "pid": alert.pid,
                    "process_name": alert.process_name,
                    "alert_id": alert.id
                })
                killed = True
            except Exception:
                # Queue down (Redis) must not block SOC triage — alert still resolves.
                killed = False

    alert.is_resolved = body.resolved
    await db.commit()
    await log_audit(
        db, action="resolve_alert", resource="alert", resource_id=str(alert.id),
        details={"resolved": body.resolved, "agent_id": str(alert.agent_id), "killed": killed},
        user_id=_user.id, username=_user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()
    await db.refresh(alert)
    return alert

@router.get("/agents", response_model=List[AgentResponse])
async def get_agents(
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user),
    active_only: bool = False,
    include_demo: bool = Query(False, description="Include demo agents"),
    site: Optional[str] = Query(None, description="Filtra per sito (da meta)"),
    limit: int = Query(100, ge=1, le=1000)
):
    from app.services.fleet import get_site, agent_status
    stmt = select(Agent)
    if active_only:
        threshold = datetime.now(timezone.utc) - timedelta(minutes=15)
        stmt = stmt.where(Agent.last_seen >= threshold)
    if not include_demo:
        stmt = stmt.where(Agent.is_demo == False)

    stmt = stmt.order_by(Agent.last_seen.desc()).limit(limit)
    result = await db.execute(stmt)
    out = []
    for a in result.scalars().all():
        if site and get_site(a) != site.strip().lower():
            continue
        out.append(AgentResponse(
            agent_id=a.agent_id, hostname=a.hostname, ip_address=a.ip_address,
            os_type=a.os_type, agent_type=a.agent_type, agent_version=a.agent_version,
            isolated=bool(a.isolated), is_demo=bool(a.is_demo), last_seen=a.last_seen,
            site=get_site(a), status=agent_status(a.last_seen),
            capabilities=a.capabilities,
        ))
    return out

@router.get("/recent")
async def get_recent_telemetry(
    db: AsyncSession = Depends(get_db),
    _user = Depends(get_current_user),
    agent_id: Optional[str] = None,
    # Tetto alto apposta: la dashboard disegna una serie temporale (~10s per
    # campione), quindi 200 punti coprono pochi minuti e il grafico non può
    # tornare indietro. 2000 è la finestra massima che vale la pena disegnare.
    limit: int = Query(50, ge=1, le=2000),
    # Modalità leggera per chi disegna serie e liste: senza i due blob JSON
    # pesanti. Una riga completa pesa ~8 KB (network_flows ~2,6 KB + processes
    # ~2 KB): 600 righe erano 4,9 MB e 1,1 s di CPU per una richiesta, e in
    # parallelo affamavano l'unico worker. Il grafico usa quattro campi.
    slim: bool = Query(False, description="Omit heavy JSON blobs (network flows, process list)"),
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
    rows = []
    for telemetry, agent in result.all():
        row = {
            "id": telemetry.id,
            "agent_id": str(telemetry.device_id),
            "hostname": agent.hostname,
            "agent_type": agent.agent_type,
            "timestamp": telemetry.timestamp,
            "cpu_usage": telemetry.cpu_usage,
            "ram_usage": telemetry.ram_usage,
            "disk_free": telemetry.disk_free,
            "disk_total": telemetry.disk_total,
        }
        if not slim:
            row.update({
                "network_sent": telemetry.network_sent,
                "network_received": telemetry.network_received,
                "processes": telemetry.processes,
                "ip_local": telemetry.ip_local,
                "ip_public": telemetry.ip_public,
                "users": telemetry.users,
                "network_flows": telemetry.network_flows,
            })
        rows.append(row)
    return rows

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
    not_resolved = or_(Alert.is_resolved == False, Alert.is_resolved == None)
    unresolved = (await db.execute(select(func.count(Alert.id)).where(not_resolved))).scalar() or 0
    current_critical = (await db.execute(select(func.count(Alert.id)).where(not_resolved, func.upper(Alert.severity) == "CRITICAL"))).scalar() or 0
    current_high = (await db.execute(select(func.count(Alert.id)).where(not_resolved, func.upper(Alert.severity) == "HIGH"))).scalar() or 0
    current_medium = (await db.execute(select(func.count(Alert.id)).where(not_resolved, func.upper(Alert.severity) == "MEDIUM"))).scalar() or 0
    current_low = (await db.execute(select(func.count(Alert.id)).where(not_resolved, func.upper(Alert.severity) == "LOW"))).scalar() or 0
    
    threshold = datetime.now(timezone.utc) - timedelta(minutes=15)
    agent_query = select(func.count(Agent.agent_id)).where(Agent.last_seen >= threshold)
    if not include_demo:
        agent_query = agent_query.where(Agent.is_demo == False)
    active_agents = (await db.execute(agent_query)).scalar() or 0
    
    # Also count demo agents separately
    demo_agent_query = select(func.count(Agent.agent_id)).where(Agent.is_demo == True, Agent.last_seen >= threshold)
    demo_agents = (await db.execute(demo_agent_query)).scalar() or 0

    # M7 Fase 8: salute flotta — isolati, stale (15m-24h), offline (>24h).
    isolated_agents = (await db.execute(
        select(func.count(Agent.agent_id)).where(Agent.isolated == True))).scalar() or 0
    stale_cut = datetime.now(timezone.utc) - timedelta(hours=24)
    stale_agents = (await db.execute(select(func.count(Agent.agent_id)).where(
        Agent.last_seen < threshold, Agent.last_seen >= stale_cut))).scalar() or 0
    offline_agents = (await db.execute(select(func.count(Agent.agent_id)).where(
        Agent.last_seen < stale_cut))).scalar() or 0

    return StatsResponse(
        total_alerts=total_alerts,
        unresolved_alerts=unresolved,
        active_agents=active_agents,
        current_critical_alerts=current_critical,
        current_high_alerts=current_high,
        current_medium_alerts=current_medium,
        current_low_alerts=current_low,
        demo_agents=demo_agents,
        events_duplicated=event_dedup.DEDUP.duplicates,
        events_seq_gaps=event_dedup.SEQ.gaps,
        events_seq_gap_events=event_dedup.SEQ.gap_events,
        isolated_agents=isolated_agents,
        stale_agents=stale_agents,
        offline_agents=offline_agents,
    )

@router.post("/report")
async def agent_report(request: Request, payload: EventSchema, db: AsyncSession = Depends(get_db), agent: Agent = Depends(get_current_agent)):
    import time as _time
    _t0 = _time.perf_counter()
    inc("aegis_events_received_total", 1, f'agent="{agent.agent_id}",type="{payload.event_type}"')
    if not await ingest_rate_guard.allow_async(str(agent.agent_id)):
        inc("aegis_events_dropped_total", 1, f'reason="rate_limited",agent="{agent.agent_id}"')
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate exceeded")
    if str(agent.agent_id) != payload.agent_id:
        inc("aegis_agent_errors_total", 1, f'agent="{agent.agent_id}",error="agent_id_mismatch"')
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Agent ID mismatch")
    data = sanitize_event(payload.model_dump())
    # Fase 5: valida Age header se presente (rifiuta negativi/enormi/non numerici/incoerenti)
    from app.core.age_validation import validate_age_header
    validate_age_header(request, payload.timestamp)
    # M1/M4: dedup persistita (Redis + memoria) sopravvive a reboot/worker.
    event_dedup.SEQ.observe(payload.agent_id, payload.boot_id, payload.seq)
    if await event_dedup.is_duplicate(payload.agent_id, payload.event_id):
        inc("aegis_events_duplicate_total", 1, f'agent="{agent.agent_id}"')
        return {"status": "duplicate"}
    try:
        await telemetry_service.process_telemetry(db, agent.agent_id, data)
    except Exception as e:
        inc("aegis_agent_errors_total", 1, f'agent="{agent.agent_id}",error="process_telemetry"')
        raise
    observe_hist("aegis_ingestion_latency_seconds", _time.perf_counter() - _t0)
    return {"status": "ok"}


@router.post("/report/batch")
async def agent_report_batch(
    request: Request,
    payload: List[Any], db: AsyncSession = Depends(get_db),
    agent: Agent = Depends(get_current_agent),
):
    """Ingestion batch: N eventi in un round-trip (storm di exec senza intasare).

    Stesse regole del singolo report, un commit per evento ma senza
    enrichment sincrono (è async fuori request path). Max 100/batch.

    La validazione è **per evento**, non per batch: il body arriva come lista
    grezza e ogni elemento è convalidato da solo. Con `List[EventSchema]`
    FastAPI convalidava la lista in blocco e UN elemento fuori schema faceva
    rispondere 422 all'intera richiesta, prima ancora di entrare qui — quindi
    24 eventi sani venivano persi per colpa di 1. Peggio: l'outbox
    dell'agente rigioca il batch respinto, quindi restava bloccato per sempre.
    Ora l'evento fuori schema è contato in `rejected` e gli altri passano.
    """
    if len(payload) > 100:
        raise HTTPException(status_code=413, detail="Max 100 events per batch")
    accepted, rejected, duplicates = 0, 0, 0
    # L'id si legge UNA volta, prima del loop, e da qui in poi si usa solo la
    # stringa. Motivo, verificato dal vivo: un commit fallito scade gli oggetti
    # ORM della sessione, quindi `agent.agent_id` dopo un errore diventa un
    # lazy-load su una sessione in corso di rollback. Nel ramo `except` quel
    # lazy-load sollevava PendingRollbackError — cioè l'error path diventava
    # esso stesso l'errore, e la richiesta rispondeva 500 invece di dichiarare
    # l'evento come `rejected`. Un evento con un NUL nel nome processo bastava,
    # e l'outbox dell'agente lo rigioca per sempre.
    agent_id = agent.agent_id
    agent_ref = str(agent_id)
    from app.core.age_validation import validate_age_header
    inc("aegis_events_received_total", len(payload), f'agent="{agent_ref}",type="batch"')
    if not await ingest_rate_guard.allow_async(agent_ref, len(payload)):
        inc("aegis_events_dropped_total", len(payload), f'reason="rate_limited",agent="{agent_ref}"')
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate exceeded")
    for raw in payload:
        try:
            item = EventSchema.model_validate(raw)
        except ValidationError as exc:
            rejected += 1
            inc("aegis_events_dropped_total", 1, f'reason="schema",agent="{agent.agent_id}"')
            logger.warning("Evento fuori schema scartato nel batch (agent=%s): %s",
                           agent_ref, exc.errors()[:2])
            continue
        if agent_ref != item.agent_id:
            rejected += 1
            continue
        # Audit L7: la validazione di `Age` è per-evento e non può abortire
        # l'intero batch (prima un solo evento stale scartava i 99 sani dopo).
        try:
            validate_age_header(request, item.timestamp)
        except HTTPException:
            rejected += 1
            inc("aegis_events_dropped_total", 1, f'reason="stale_event",agent="{agent_ref}"')
            continue
        event_dedup.SEQ.observe(item.agent_id, item.boot_id, item.seq)
        if await event_dedup.is_duplicate(item.agent_id, item.event_id):
            duplicates += 1
            inc("aegis_events_duplicate_total", 1, f'agent="{agent_ref}"')
            continue
        try:
            await telemetry_service.process_telemetry(db, agent_id, sanitize_event(item.model_dump()))
            accepted += 1
        except Exception as exc:
            rejected += 1
            # Audit L2: senza rollback la sessione resta pending-rollback e
            # TUTTI gli eventi successivi del batch fallivano: un solo evento
            # rotto ne scartava fino a 99 sani.
            # Ordine deliberato: rollback PRIMA di metrica e log. Il commit
            # fallito ha già scaduto gli oggetti ORM; qualunque accesso a
            # `agent.*` prima del rollback è un accesso al database che
            # fallisce a sua volta.
            try:
                await db.rollback()
            except Exception:
                logger.exception("Rollback fallito durante l'ingestion batch")
            inc("aegis_agent_errors_total", 1, f'agent="{agent_ref}",error="process_telemetry"')
            logger.warning("Evento scartato nel batch (agent=%s): %s", agent_ref, exc)
    set_gauge("aegis_queue_depth", accepted, f'agent="{agent_ref}",stage="ingest"')
    return {"status": "ok", "accepted": accepted, "rejected": rejected, "duplicates": duplicates}

@router.post("/heartbeat")
async def agent_heartbeat(data: dict, db: AsyncSession = Depends(get_db), agent: Agent = Depends(get_current_agent)):
    agent.last_seen = datetime.now(timezone.utc)
    # Fleet management (OTA): agents report version/capabilities on heartbeat.
    try:
        if isinstance(data, dict):
            if data.get("agent_version"):
                agent.agent_version = str(data.get("agent_version"))[:50]
            if isinstance(data.get("capabilities"), (dict, list)):
                agent.capabilities = data.get("capabilities")
    except Exception:
        pass
    # M1 Discovery v2: auto-sync DiscoveredHost on every heartbeat so the
    # Discovery UI no longer needs the manual "Sync Agents" button.
    try:
        if agent.ip_address:
            from app.database.models import DiscoveredHost
            r = await db.execute(select(DiscoveredHost).where(DiscoveredHost.ip_address == agent.ip_address))
            host = r.scalars().first()
            if host:
                threshold_ok = True  # just heartbeated -> active
                if (agent.agent_type or "").lower() == "aegis-guard":
                    host.guard_status = "active" if threshold_ok else host.guard_status
                elif (agent.agent_type or "").lower() == "nodetrace":
                    host.nodetrace_status = "active" if threshold_ok else host.nodetrace_status
                host.last_seen = datetime.now(timezone.utc)
    except Exception:
        pass  # never break heartbeat on sync errors
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


@router.get("/commands/batch")
async def get_agent_commands_batch(
    agent: Agent = Depends(get_current_agent),
    db: AsyncSession = Depends(get_db),
    n: int = Query(50, ge=1, le=100),
):
    """Drena fino a N comandi in un round-trip (sotto burst, niente 25s di poll).

    Gli agenti provano prima qui e cadono sul singolo in caso di 404
    (brain vecchio). Ritorna sempre una lista (anche vuota).
    """
    import redis.asyncio as redis
    from app.core.redis_utils import get_redis_url
    rc = redis.from_url(get_redis_url(), decode_responses=True)
    queue_name = f"aegis:commands:{agent.agent_id}"
    out = []
    try:
        for _ in range(n):
            raw = await rc.lpop(queue_name)
            if not raw:
                break
            import json
            try:
                out.append(json.loads(raw))
            except Exception:
                continue
    except Exception:
        pass
    return out


class CommandAck(BaseModel):
    command: str
    status: str = "ok"
    details: Optional[str] = None
    alert_id: Optional[int] = None


@router.post("/commands/ack")
async def ack_agent_command(
    payload: CommandAck,
    db: AsyncSession = Depends(get_db),
    agent: Agent = Depends(get_current_agent),
):
    """EDR command acknowledgement (CrowdStrike-style action confirmation).

    Agents POST here after executing a queued command so the SOC sees
    ok/failed instead of fire-and-forget. If alert_id is supplied the
    matching RemediationAction is updated too.
    """
    if payload.alert_id:
        r = await db.execute(select(RemediationAction).where(RemediationAction.id == payload.alert_id))
        rec = r.scalars().first()
        if rec:
            rec.status = payload.status
            if payload.details:
                rec.details = (payload.details or "")[:2000]
            await db.commit()
    # Contain/release tracking: SOC sees at a glance which hosts are isolated.
    try:
        cmd = (payload.command or "").upper()
        if cmd == "ISOLATE_HOST" and payload.status == "ok":
            agent.isolated = True
            await db.commit()
        elif cmd in ("DEISOLATE_HOST", "DEISOLATE") and payload.status == "ok":
            agent.isolated = False
            await db.commit()
    except Exception:
        pass
    return {"status": "acked", "command": payload.command, "agent_id": str(agent.agent_id)}

@router.get("/remediations")
async def get_remediation_actions(limit: int = 20, db: AsyncSession = Depends(get_db), _user = Depends(get_current_user)):
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


@router.get("/alerts/{alert_id}/process-tree")
async def alert_process_tree(
    alert_id: int, db: AsyncSession = Depends(get_db), _user = Depends(get_current_user),
    limit: int = Query(200, ge=10, le=1000),
):
    """Albero forense pid->parent per l'alert: risale la catena e scende ai figli."""
    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    result = await db.execute(
        select(Alert).where(Alert.agent_id == alert.agent_id)
        .order_by(Alert.timestamp.desc()).limit(limit))
    siblings = result.scalars().all()
    by_pid: dict = {}
    for a in siblings:
        if a.pid:
            by_pid.setdefault(a.pid, a)
    children: dict = {}
    for a in siblings:
        if a.parent_pid:
            children.setdefault(a.parent_pid, []).append(a.pid)

    def node(a):
        return {"alert_id": a.id, "pid": a.pid, "parent_pid": a.parent_pid,
                "process_name": a.process_name, "process_path": a.process_path,
                "severity": a.severity, "event_type": a.event_type,
                "timestamp": a.timestamp.isoformat() if a.timestamp else None,
                "is_target": a.id == alert_id}

    chain, seen, cur = [], set(), alert
    while cur and cur.pid and cur.pid not in seen:
        seen.add(cur.pid)
        chain.append(node(cur))
        parent = None
        if cur.parent_pid and cur.parent_pid in by_pid:
            parent = by_pid[cur.parent_pid]
        cur = parent
    chain = list(reversed(chain))
    target_pids = seen or ({alert.pid} if alert.pid else set())
    descendants = []
    stack = [p for pids in [children.get(p, []) for p in target_pids] for p in pids if p not in seen]
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        if p in by_pid:
            descendants.append(node(by_pid[p]))
            stack.extend(c for c in children.get(p, []) if c not in seen)
    return {"alert_id": alert.id, "agent_id": str(alert.agent_id),
            "ancestor_chain": chain, "descendants": descendants}


class IsolateRequest(BaseModel):
    reason: Optional[str] = Field(None, max_length=500)


def _require_soc(user):
    # M7 Fase 8: responder incluso nelle contain actions (estensione, mai
    # restrizione dei ruoli esistenti).
    if (user.role or "user").lower() not in ("admin", "analyst", "responder"):
        raise HTTPException(status_code=403, detail="Contain actions require responder/analyst/admin role")


@router.post("/agents/{agent_id}/isolate")
async def isolate_agent(
    agent_id: str, payload: IsolateRequest, request: Request,
    db: AsyncSession = Depends(get_db), _user = Depends(get_current_user),
):
    import uuid as _uuid
    _require_soc(_user)
    try:
        agent_uuid = _uuid.UUID(agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent_id format")
    agent = await db.get(Agent, agent_uuid)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    try:
        await telemetry_service.send_command_to_agent(agent.agent_id, {
            "command": "ISOLATE_HOST", "reason": payload.reason or "SOC contain"})
        queued = True
    except Exception:
        queued = False
    await log_audit(
        db, action="agent_isolate", resource="agent", resource_id=str(agent.agent_id),
        details={"reason": payload.reason, "queued": queued},
        user_id=_user.id, username=_user.username,
        ip_address=request.client.host if request else None)
    await db.commit()
    return {"status": "queued" if queued else "queue_unavailable",
            "agent_id": str(agent.agent_id), "isolated": agent.isolated}


@router.post("/agents/{agent_id}/release")
async def release_agent(
    agent_id: str, request: Request,
    db: AsyncSession = Depends(get_db), _user = Depends(get_current_user),
):
    import uuid as _uuid
    _require_soc(_user)
    try:
        agent_uuid = _uuid.UUID(agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent_id format")
    agent = await db.get(Agent, agent_uuid)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    try:
        await telemetry_service.send_command_to_agent(agent.agent_id, {"command": "DEISOLATE_HOST"})
        queued = True
    except Exception:
        queued = False
    await log_audit(
        db, action="agent_release", resource="agent", resource_id=str(agent.agent_id),
        details={"queued": queued},
        user_id=_user.id, username=_user.username,
        ip_address=request.client.host if request else None)
    await db.commit()
    return {"status": "queued" if queued else "queue_unavailable",
            "agent_id": str(agent.agent_id), "isolated": agent.isolated}


class SiteAssign(BaseModel):
    site: str = Field(..., max_length=64)


@router.patch("/agents/{agent_id}/site")
async def assign_agent_site(
    agent_id: str, payload: SiteAssign, request: Request,
    db: AsyncSession = Depends(get_db), _user = Depends(get_current_user),
):
    """Assegna un agente a un sito (meta JSON, migration-free). Triage+."""
    from app.services.fleet import get_site, set_site_meta
    if (_user.role or "user").lower() not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Site assignment requires analyst or admin role")
    import uuid as _uuid
    try:
        agent_uuid = _uuid.UUID(agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent_id format")
    agent = await db.get(Agent, agent_uuid)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    try:
        new_meta = set_site_meta(agent.meta, payload.site)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    old_site = get_site(agent)
    agent.meta = new_meta
    await log_audit(
        db, action="agent_site_assign", resource="agent", resource_id=str(agent.agent_id),
        details={"old_site": old_site, "new_site": new_meta["site"]},
        user_id=_user.id, username=_user.username,
        ip_address=request.client.host if request else None)
    await db.commit()
    return {"agent_id": str(agent.agent_id), "old_site": old_site,
            "site": new_meta["site"]}
