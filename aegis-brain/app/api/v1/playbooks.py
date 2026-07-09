from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional
from datetime import datetime
from app.database.connection import get_db
from app.database.models import Playbook, PlaybookAction, PlaybookExecution
from app.core.deps import get_current_user
from app.core.audit import log_audit
from pydantic import BaseModel

router = APIRouter(tags=["Playbooks"])

class PlaybookActionCreate(BaseModel):
    action_type: str
    target: str
    params: Optional[dict] = None
    order: int = 0

class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    is_active: bool = True
    trigger_event_type: Optional[str] = None
    trigger_severity: Optional[str] = None
    trigger_process_name: Optional[str] = None
    trigger_condition: Optional[str] = None
    actions: List[PlaybookActionCreate] = []

class PlaybookUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    trigger_event_type: Optional[str] = None
    trigger_severity: Optional[str] = None
    trigger_process_name: Optional[str] = None
    trigger_condition: Optional[str] = None

@router.get("/playbooks")
async def list_playbooks(db: AsyncSession = Depends(get_db), _user = Depends(get_current_user)):
    result = await db.execute(select(Playbook).order_by(Playbook.name))
    playbooks = []
    for p in result.scalars().all():
        actions_result = await db.execute(
            select(PlaybookAction).where(PlaybookAction.playbook_id == p.id).order_by(PlaybookAction.order)
        )
        actions = [{"id": a.id, "action_type": a.action_type, "target": a.target, "params": a.params, "order": a.order} for a in actions_result.scalars().all()]
        playbooks.append({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "is_active": p.is_active,
            "trigger_event_type": p.trigger_event_type,
            "trigger_severity": p.trigger_severity,
            "trigger_process_name": p.trigger_process_name,
            "trigger_condition": p.trigger_condition,
            "actions": actions,
            "created_at": p.created_at.isoformat() if p.created_at else None,
        })
    return playbooks

@router.post("/playbooks")
async def create_playbook(data: PlaybookCreate, db: AsyncSession = Depends(get_db), _user = Depends(get_current_user)):
    existing = await db.execute(select(Playbook).where(Playbook.name == data.name))
    if existing.scalars().first():
        raise HTTPException(status_code=400, detail="Playbook with this name already exists")
    
    playbook = Playbook(
        name=data.name,
        description=data.description,
        is_active=data.is_active,
        trigger_event_type=data.trigger_event_type,
        trigger_severity=data.trigger_severity,
        trigger_process_name=data.trigger_process_name,
        trigger_condition=data.trigger_condition,
    )
    db.add(playbook)
    await db.flush()

    for i, a in enumerate(data.actions):
        action = PlaybookAction(
            playbook_id=playbook.id,
            action_type=a.action_type,
            target=a.target,
            params=a.params,
            order=a.order or i,
        )
        db.add(action)

    await db.commit()
    await db.refresh(playbook)
    return {"id": playbook.id, "name": playbook.name, "detail": "Playbook created"}

@router.put("/playbooks/{playbook_id}")
async def update_playbook(playbook_id: int, data: PlaybookUpdate, db: AsyncSession = Depends(get_db), _user = Depends(get_current_user)):
    playbook = await db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    if data.name is not None:
        playbook.name = data.name
    if data.description is not None:
        playbook.description = data.description
    if data.is_active is not None:
        playbook.is_active = data.is_active
    if data.trigger_event_type is not None:
        playbook.trigger_event_type = data.trigger_event_type
    if data.trigger_severity is not None:
        playbook.trigger_severity = data.trigger_severity
    if data.trigger_process_name is not None:
        playbook.trigger_process_name = data.trigger_process_name
    if data.trigger_condition is not None:
        playbook.trigger_condition = data.trigger_condition
    
    await db.commit()
    return {"detail": "Playbook updated"}

@router.delete("/playbooks/{playbook_id}")
async def delete_playbook(playbook_id: int, db: AsyncSession = Depends(get_db), _user = Depends(get_current_user)):
    playbook = await db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    await db.delete(playbook)
    await db.commit()
    return {"detail": "Playbook deleted"}

@router.get("/playbook-executions")
async def list_executions(limit: int = 50, db: AsyncSession = Depends(get_db), _user = Depends(get_current_user)):
    result = await db.execute(
        select(PlaybookExecution).order_by(PlaybookExecution.started_at.desc()).limit(limit)
    )
    execs = []
    for e in result.scalars().all():
        execs.append({
            "id": e.id,
            "playbook_id": e.playbook_id,
            "alert_id": e.alert_id,
            "status": e.status,
            "result": e.result,
            "started_at": e.started_at.isoformat() if e.started_at else None,
            "completed_at": e.completed_at.isoformat() if e.completed_at else None,
        })
    return execs
