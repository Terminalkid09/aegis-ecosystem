"""SOC incidents — raggruppa alert, triage status, assignee, timeline."""
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.deps import get_current_user
from app.database.connection import get_db
from app.database.models import (
    INCIDENT_STATUSES,
    SEVERITY_RANK,
    Agent,
    Alert,
    Incident,
    IncidentAlert,
    User,
)

router = APIRouter(tags=["Incidents"])


def _require_incident_operator(user):
    if (user.role or "user").lower() not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Incident changes require analyst or admin role")


class IncidentCreate(BaseModel):
    title: str = Field(..., max_length=255)
    alert_ids: List[int] = Field(default_factory=list, max_length=500)
    assignee_id: Optional[int] = None


class IncidentPatch(BaseModel):
    title: Optional[str] = Field(None, max_length=255)
    status: Optional[str] = None
    assignee_id: Optional[int] = None
    note: Optional[str] = Field(
        None, max_length=2000,
        description="Nota analyst: registrata in audit trail, mai diagnosi automatica")


def _severity_of(alerts) -> str:
    best, rank = "MEDIUM", -1
    for a in alerts:
        r = SEVERITY_RANK.get((a.severity or "").upper(), 0)
        if r > rank:
            rank, best = r, (a.severity or "MEDIUM").upper()
    return best


async def _incident_out(db: AsyncSession, inc: Incident) -> dict:
    r = await db.execute(select(Alert).join(
        IncidentAlert, IncidentAlert.alert_id == Alert.id).where(
        IncidentAlert.incident_id == inc.id).order_by(Alert.timestamp.asc()))
    alerts = r.scalars().all()
    assignee = None
    if inc.assignee_id:
        u = await db.get(User, inc.assignee_id)
        assignee = u.username if u else None
    return {
        "id": inc.id, "title": inc.title, "severity": inc.severity,
        "status": inc.status, "assignee_id": inc.assignee_id,
        "assignee": assignee, "agent_id": inc.agent_id,
        "alert_count": len(alerts),
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
        "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        "timeline": [
            {"id": a.id, "timestamp": a.timestamp.isoformat() if a.timestamp else None,
             "severity": a.severity, "process_name": a.process_name,
             "event_type": a.event_type, "description": a.description[:300],
             "is_resolved": a.is_resolved}
            for a in alerts
        ],
    }


@router.get("/incidents")
async def list_incidents(
    db: AsyncSession = Depends(get_db), user=Depends(get_current_user),
    status: Optional[str] = Query(None), limit: int = Query(50, ge=1, le=200),
):
    stmt = select(Incident).order_by(Incident.updated_at.desc()).limit(limit)
    if status:
        if status not in INCIDENT_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        stmt = stmt.where(Incident.status == status)
    result = await db.execute(stmt)
    return {"items": [await _incident_out(db, i) for i in result.scalars().all()]}


@router.post("/incidents")
async def create_incident(
    payload: IncidentCreate, request: Request,
    db: AsyncSession = Depends(get_db), user=Depends(get_current_user),
):
    _require_incident_operator(user)
    alerts = []
    if payload.alert_ids:
        r = await db.execute(select(Alert).where(Alert.id.in_(payload.alert_ids)))
        alerts = r.scalars().all()
        if len(alerts) != len(set(payload.alert_ids)):
            raise HTTPException(status_code=400, detail="Some alert_ids not found")
    if payload.assignee_id:
        if not await db.get(User, payload.assignee_id):
            raise HTTPException(status_code=400, detail="Assignee not found")
    agent_id = str(alerts[0].agent_id) if alerts and len({str(a.agent_id) for a in alerts}) == 1 else None
    inc = Incident(
        title=payload.title, severity=_severity_of(alerts) if alerts else "MEDIUM",
        status="open", assignee_id=payload.assignee_id, agent_id=agent_id,
        created_by=user.id,
    )
    db.add(inc)
    await db.flush()
    for a in alerts:
        db.add(IncidentAlert(incident_id=inc.id, alert_id=a.id))
    await db.commit()
    await db.refresh(inc)
    await log_audit(db, action="incident_create", resource="incident", resource_id=str(inc.id),
                    details={"title": payload.title, "alerts": len(alerts)},
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return await _incident_out(db, inc)


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: int, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    inc = await db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return await _incident_out(db, inc)


@router.patch("/incidents/{incident_id}")
async def update_incident(
    incident_id: int, payload: IncidentPatch, request: Request,
    db: AsyncSession = Depends(get_db), user=Depends(get_current_user),
):
    _require_incident_operator(user)
    inc = await db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    if payload.title is not None:
        inc.title = payload.title
    if payload.status is not None:
        if payload.status not in INCIDENT_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        inc.status = payload.status
        if payload.status in ("resolved", "closed"):
            inc.resolved_at = datetime.now(timezone.utc)
        else:
            inc.resolved_at = None
    if payload.assignee_id is not None:
        if payload.assignee_id and not await db.get(User, payload.assignee_id):
            raise HTTPException(status_code=400, detail="Assignee not found")
        inc.assignee_id = payload.assignee_id or None
    await db.commit()
    await db.refresh(inc)
    details = {"status": inc.status, "assignee_id": inc.assignee_id}
    action = "incident_update"
    if payload.note:
        # Feedback analyst: audit trail dedicato (niente colonna dedicata,
        # la nota resta ricercabile nei log con action=incident_note).
        action = "incident_note"
        details["note"] = payload.note[:2000]
    await log_audit(db, action=action, resource="incident", resource_id=str(inc.id),
                    details=details,
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return await _incident_out(db, inc)


@router.post("/incidents/{incident_id}/alerts")
async def attach_alerts(
    incident_id: int, alert_ids: List[int], request: Request,
    db: AsyncSession = Depends(get_db), user=Depends(get_current_user),
):
    _require_incident_operator(user)
    inc = await db.get(Incident, incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    r = await db.execute(select(Alert).where(Alert.id.in_(alert_ids[:500])))
    alerts = r.scalars().all()
    added = 0
    for a in alerts:
        exists = await db.get(IncidentAlert, (incident_id, a.id))
        if not exists:
            db.add(IncidentAlert(incident_id=incident_id, alert_id=a.id))
            added += 1
    # re-rank severity
    full = await db.execute(select(Alert).join(
        IncidentAlert, IncidentAlert.alert_id == Alert.id).where(
        IncidentAlert.incident_id == incident_id))
    inc.severity = _severity_of(full.scalars().all())
    await db.commit()
    await db.refresh(inc)
    await log_audit(db, action="incident_attach", resource="incident", resource_id=str(inc.id),
                    details={"added": added}, user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return await _incident_out(db, inc)


@router.post("/incidents/auto-group")
async def auto_group(
    request: Request, db: AsyncSession = Depends(get_db), user=Depends(get_current_user),
):
    _require_incident_operator(user)
    """Raggruppa alert simili (stessa tecnica/processo/host/finestra) invece
    di un incidente per agente: meno rumore, più contesto."""
    from app.core.config import settings
    from app.services.incident_grouping import suggest_groups, group_title
    r = await db.execute(
        select(Alert).where(Alert.is_resolved.is_(False)).order_by(Alert.timestamp.asc()).limit(1000))
    ungrouped = []
    for a in r.scalars().all():
        link = await db.execute(select(IncidentAlert).where(IncidentAlert.alert_id == a.id).limit(1))
        if not link.scalars().first():
            ungrouped.append(a)
    groups = suggest_groups(ungrouped, settings.CORR_AUTOGROUP_WINDOW_MIN)
    created = []
    for key, alerts in groups.items():
        ag = await db.get(Agent, alerts[0].agent_id)
        hostname = ag.hostname if ag and ag.hostname else ""
        inc = Incident(
            title=group_title(key, hostname),
            severity=_severity_of(alerts), status="open",
            agent_id=key[0], created_by=user.id,
        )
        db.add(inc)
        await db.flush()
        for a in alerts:
            db.add(IncidentAlert(incident_id=inc.id, alert_id=a.id))
        created.append(inc.id)
    await db.commit()
    await log_audit(db, action="incident_autogroup", resource="incident",
                    details={"created": len(created),
                             "window_min": settings.CORR_AUTOGROUP_WINDOW_MIN},
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return {"created": len(created), "incident_ids": created}
