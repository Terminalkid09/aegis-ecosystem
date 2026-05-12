from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Optional
import redis
import json
import os

from api.schemas import AlertResponse, AgentResponse, StatsResponse, ResolveRequest
from api.middleware import verify_api_key
from database.connection import get_db
from database.models import Alert, Agent

router = APIRouter(dependencies=[Depends(verify_api_key)])

# Redis configuration for commands
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

@router.get("/alerts", response_model=list[AlertResponse])
def get_alerts(
    agent_id:    Optional[str]  = Query(None),
    severity:    Optional[str]  = Query(None),
    is_resolved: Optional[bool] = Query(None),
    limit:       int            = Query(100, ge=1, le=1000),
    offset:      int            = Query(0,   ge=0),
    db: Session = Depends(get_db)
):
    query = db.query(Alert)
    if agent_id:
        query = query.filter(Alert.agent_id.cast(str).ilike(f"%{agent_id}%"))
    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if is_resolved is not None:
        query = query.filter(Alert.is_resolved == is_resolved)
    return query.order_by(Alert.timestamp.desc()).offset(offset).limit(limit).all()

@router.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert

@router.patch("/alerts/{alert_id}/resolve", response_model=AlertResponse)
def resolve_alert(alert_id: int, body: ResolveRequest, db: Session = Depends(get_db)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    # Se l'alert non era già risolto e stiamo risolvendo, invia comando di KILL
    if not alert.is_resolved and body.resolved:
        if alert.pid:
            command = {
                "command": "KILL_PROCESS",
                "pid": alert.pid,
                "process_name": alert.process_name,
                "alert_id": alert.id
            }
            # Coda specifica per l'agente
            queue_name = f"aegis:commands:{alert.agent_id}"
            redis_client.lpush(queue_name, json.dumps(command))
            # Mantieni solo gli ultimi 100 comandi
            redis_client.ltrim(queue_name, 0, 99)

    alert.is_resolved = body.resolved
    db.commit()
    db.refresh(alert)
    return alert

@router.get("/agents", response_model=list[AgentResponse])
def get_agents(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0), db: Session = Depends(get_db)):
    return db.query(Agent).order_by(Agent.last_seen.desc()).offset(offset).limit(limit).all()

@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    # Totale storico degli alert
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    # Alert non ancora risolti (il rischio attuale)
    base_query = db.query(func.count(Alert.id)).filter(Alert.is_resolved == False)
    
    return StatsResponse(
        total_alerts=total_alerts,
        unresolved_alerts=base_query.scalar() or 0,
        current_critical_alerts=base_query.filter(Alert.severity == "CRITICAL").scalar() or 0,
        current_high_alerts=base_query.filter(Alert.severity == "HIGH").scalar() or 0,
        current_medium_alerts=base_query.filter(Alert.severity == "MEDIUM").scalar() or 0,
        current_low_alerts=base_query.filter(Alert.severity == "LOW").scalar() or 0,
        active_agents=db.query(func.count(Agent.agent_id)).scalar() or 0,
    )
