"""OCSF export endpoints — interoperabilità con SIEM esterni.

Espone gli alert e la telemetria nel formato OCSF 1.4.0 (JSON o NDJSON per
pipeline di ingestion) così che Splunk / Elastic / Sentinel / Security Lake
possano consumare Aegis senza un parser custom. Vedi `app/services/ocsf.py`
per la mappatura.
"""
import json
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import get_current_user
from app.database.connection import get_db
from app.database.models import Agent, Alert
from app.services import ocsf as ocsf_service

router = APIRouter(tags=["OCSF Export"])


@router.get("/schema")
async def ocsf_schema(user=Depends(get_current_user)):
    """Mappatura supportata + versione schema (per integratori e UI)."""
    return ocsf_service.schema_description()


@router.get("/alerts")
async def export_alerts(
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None, description="Filtra per severità (high, critical…)"),
    unresolved_only: bool = Query(False),
    download: bool = Query(False, description="NDJSON invece di JSON (per ingestion batch)"),
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Esporta gli alert come OCSF Detection Finding (class 2004)."""
    stmt = select(Alert).order_by(Alert.timestamp.desc()).limit(limit)
    if severity:
        stmt = stmt.where(Alert.severity == severity.upper())
    if unresolved_only:
        stmt = stmt.where(Alert.is_resolved.is_(False))
    result = await db.execute(stmt)
    alerts = result.scalars().all()

    # Gli agenti sono caricati in blocco: 100 alert non devono fare 100 query.
    agent_ids = {a.agent_id for a in alerts}
    agents: Dict[Any, Agent] = {}
    if agent_ids:
        agent_rows = await db.execute(select(Agent).where(Agent.agent_id.in_(agent_ids)))
        agents = {a.agent_id: a for a in agent_rows.scalars().all()}

    events: List[Dict[str, Any]] = [
        ocsf_service.alert_to_ocsf(a, agents.get(a.agent_id)) for a in alerts
    ]

    if download:
        body = "\n".join(json.dumps(e, default=str) for e in events)
        return Response(
            content=body,
            media_type="application/x-ndjson",
            headers={"Content-Disposition": 'attachment; filename="aegis-alerts.ocsf.ndjson"'},
        )
    return {
        "ocsf_version": ocsf_service.OCSF_VERSION,
        "count": len(events),
        "events": events,
    }


@router.get("/alerts/{alert_id}")
async def export_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    """Esporta un singolo alert in OCSF (utile per push puntuali al SIEM)."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalars().first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    agent_row = await db.execute(select(Agent).where(Agent.agent_id == alert.agent_id))
    agent = agent_row.scalars().first()
    return ocsf_service.alert_to_ocsf(alert, agent)


class ConvertBody(BaseModel):
    """Evento interno Aegis (o alert) da convertire. `kind` sceglie la classe."""
    kind: str = "alert"          # "alert" | "process"
    event: Dict[str, Any]


@router.post("/convert")
async def convert_event(payload: ConvertBody, user=Depends(get_current_user)):
    """Converte un evento Aegis arbitrario in OCSF.

    Serve per pipeline esterne e test: il produttore manda il payload interno
    e riceve l'oggetto OCSF pronto per l'ingestion, senza condividere il DB.
    """
    if payload.kind == "process":
        return ocsf_service.process_activity_to_ocsf(payload.event)
    if payload.kind == "alert":
        return ocsf_service.alert_to_ocsf(payload.event)
    raise HTTPException(status_code=400, detail="kind must be 'alert' or 'process'")
