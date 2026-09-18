"""Gestione regole YARA e scansioni on-demand via agenti.

Flusso:
  - CRUD regole in DB (solo admin/analyst: le mutazioni regole = perm "rules");
  - POST /agents/{id}/scan: spedisce YARA_SCAN con regole ATTIVE concatenate
    e i target richiesti; Guard spawn-a yara64.exe e ogni match torna come
    evento YARA_MATCH (alert HIGH + ricercabile in Log Search).

Perché le regole viaggiano intere nel comando: le firme YARA sono di centinaia
di byte, la coda comandi ha tetto 100 messaggi per agente — nessun problema
di dimensione, e l'agente non ha bisogno di un secondo canale di config.
"""
from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.deps import get_current_user, require_perm
from app.core.logging import get_logger
from app.database.connection import get_db
from app.database.models import Agent, YaraRule
from app.services.telemetry_service import send_command_to_agent

logger = get_logger(__name__)
router = APIRouter(tags=["YARA"])

MAX_RULES_PER_SCAN = 50
MAX_RULE_CONTENT = 64 * 1024
MAX_TARGETS = 20


class YaraRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=MAX_RULE_CONTENT)
    is_active: bool = True


class YaraRuleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    content: Optional[str] = Field(None, min_length=1, max_length=MAX_RULE_CONTENT)
    is_active: Optional[bool] = None


class ScanRequest(BaseModel):
    targets: List[str] = Field(min_length=1, max_length=MAX_TARGETS)
    rule_ids: Optional[List[int]] = Field(None, max_length=MAX_RULES_PER_SCAN)


def _validate_rule_content(content: str) -> None:
    """Validazione minima: il contenuto deve sembrare una regola YARA.
    La validità sintattica completa la dice il compilatore (brain: regola
    scartata con errore; agente: yara exit>=2, errore nell'ack)."""
    stripped = content.strip()
    if not any(k in stripped for k in ("rule ", "import ", "private rule", "global rule")):
        raise HTTPException(status_code=422,
                            detail="Content does not look like a YARA rule (missing 'rule ...')")


async def _get_agent(db: AsyncSession, agent_id: str) -> Agent:
    try:
        agent_uuid = uuid.UUID(agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent_id format")
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_uuid))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.get("/rules")
async def list_rules(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    result = await db.execute(select(YaraRule).order_by(YaraRule.id.desc()))
    rules = result.scalars().all()
    return {"items": [
        {"id": r.id, "name": r.name, "is_active": r.is_active,
         "created_at": r.created_at.isoformat() if r.created_at else None,
         "content": r.content}
        for r in rules
    ]}


@router.post("/rules")
async def create_rule(payload: YaraRuleCreate, request: Request,
                      db: AsyncSession = Depends(get_db),
                      user=Depends(require_perm("rules"))):
    _validate_rule_content(payload.content)
    rule = YaraRule(name=payload.name, content=payload.content,
                    is_active=payload.is_active, created_by=user.id)
    db.add(rule)
    await log_audit(db, action="yara_rule_create", resource=f"yara_rule:{payload.name}",
                    details={"active": payload.is_active}, user_id=user.id,
                    username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return {"id": rule.id, "name": rule.name, "is_active": rule.is_active}


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: int, payload: YaraRuleUpdate, request: Request,
                      db: AsyncSession = Depends(get_db),
                      user=Depends(require_perm("rules"))):
    result = await db.execute(select(YaraRule).where(YaraRule.id == rule_id))
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    if payload.name is not None:
        rule.name = payload.name
    if payload.content is not None:
        _validate_rule_content(payload.content)
        rule.content = payload.content
    if payload.is_active is not None:
        rule.is_active = payload.is_active
    await log_audit(db, action="yara_rule_update", resource=f"yara_rule:{rule_id}",
                    details={"active": rule.is_active}, user_id=user.id,
                    username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return {"id": rule.id, "name": rule.name, "is_active": rule.is_active}


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: int, request: Request,
                      db: AsyncSession = Depends(get_db),
                      user=Depends(require_perm("rules"))):
    result = await db.execute(select(YaraRule).where(YaraRule.id == rule_id))
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await log_audit(db, action="yara_rule_delete", resource=f"yara_rule:{rule_id}",
                    details={}, user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return {"deleted": rule_id}


@router.post("/agents/{agent_id}/scan")
async def scan_agent(agent_id: str, payload: ScanRequest, request: Request,
                     db: AsyncSession = Depends(get_db),
                     user=Depends(require_perm("respond", "triage"))):
    """Lancia YARA sull'agente con le regole attive (o quelle scelte)."""
    agent = await _get_agent(db, agent_id)

    query = select(YaraRule).where(YaraRule.is_active == True)  # noqa: E712
    if payload.rule_ids:
        query = query.where(YaraRule.id.in_(payload.rule_ids))
    result = await db.execute(query)
    rules = result.scalars().all()
    if not rules:
        raise HTTPException(status_code=422, detail="No active YARA rule")

    rules_yara = "\n\n".join(r.content for r in rules[:MAX_RULES_PER_SCAN])
    try:
        await send_command_to_agent(str(agent.agent_id), {
            "command": "YARA_SCAN",
            "rules_yara": rules_yara,
            "targets": payload.targets,
        })
    except Exception as exc:
        raise HTTPException(status_code=503,
                            detail=f"Coda comandi non disponibile: {exc}")

    await log_audit(db, action="yara_scan", resource=f"agent:{agent.agent_id}",
                    details={"targets": payload.targets,
                             "rules": [r.id for r in rules[:MAX_RULES_PER_SCAN]]},
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return {"queued": True, "agent_id": str(agent.agent_id),
            "rules_sent": min(len(rules), MAX_RULES_PER_SCAN),
            "note": "Matches will arrive as 'yara_match' alerts and are searchable in Log Search"}
