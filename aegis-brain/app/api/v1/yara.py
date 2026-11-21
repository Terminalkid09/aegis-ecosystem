"""Gestione regole YARA, feed firmati e scansioni on-demand via agenti.

Flusso:
  - CRUD regole in DB (solo admin/analyst: le mutazioni regole = perm "rules");
  - POST /agents/{id}/scan: spedisce YARA_SCAN con regole ATTIVE concatenate
    e i target richiesti; Guard spawn-a yara64.exe e ogni match torna come
    evento YARA_MATCH (alert HIGH + ricercabile in Log Search).

Perché le regole viaggiano intere nel comando: le firme YARA sono di centinaia
di byte, la coda comandi ha tetto 100 messaggi per agente — nessun problema
di dimensione, e l'agente non ha bisogno di un secondo canale di config.

Le regole possono essere manuali o importate da un feed firmato. Le seconde
sono read-only via API: si aggiornano dal feed, non a mano, altrimenti il
prossimo sync sovrascriverebbe la modifica silenziosamente.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.config import settings
from app.core.deps import get_current_user, require_perm
from app.core.logging import get_logger
from app.database.connection import get_db
from app.database.models import Agent, YaraFeedState, YaraRule
from app.services import yara_feed
from app.services.telemetry_service import send_command_to_agent

logger = get_logger(__name__)
router = APIRouter(tags=["YARA"])

MAX_RULES_PER_SCAN = 50
MAX_RULE_CONTENT = 64 * 1024
MAX_TARGETS = 20
Severity = Literal["low", "medium", "high", "critical"]


class YaraRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=MAX_RULE_CONTENT)
    is_active: bool = True
    severity: Severity = "high"
    description: Optional[str] = Field(None, max_length=1000)
    tags: Optional[List[str]] = Field(None, max_length=20)
    mitre_technique_id: Optional[str] = Field(None, pattern=r"^T\d{4}(?:\.\d{3})?$")


class YaraRuleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=128)
    content: Optional[str] = Field(None, min_length=1, max_length=MAX_RULE_CONTENT)
    is_active: Optional[bool] = None
    severity: Optional[Severity] = None
    description: Optional[str] = Field(None, max_length=1000)
    tags: Optional[List[str]] = Field(None, max_length=20)
    mitre_technique_id: Optional[str] = Field(None, pattern=r"^T\d{4}(?:\.\d{3})?$")


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


def _clean_tags(tags: Optional[List[str]]) -> Optional[List[str]]:
    if tags is None:
        return None
    out: List[str] = []
    for raw in tags:
        tag = (raw or "").strip()
        if not tag or len(tag) > 64:
            raise HTTPException(status_code=422, detail="YARA tags must be 1-64 characters")
        if tag not in out:
            out.append(tag)
    if len(out) > 20:
        raise HTTPException(status_code=422, detail="At most 20 YARA tags are allowed")
    return out


def _rule_view(rule: YaraRule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "is_active": rule.is_active,
        "severity": rule.severity,
        "description": rule.description,
        "tags": rule.tags or [],
        "mitre_technique_id": rule.mitre_technique_id,
        "source": rule.source,
        "source_version": rule.source_version,
        "managed": rule.managed,
        "last_synced_at": rule.last_synced_at.isoformat() if rule.last_synced_at else None,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "content": rule.content,
    }


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


@router.get("/feeds/status")
async def feed_status(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    """Stato dei feed configurati. Nessun segreto: URL redatti e fingerprint."""
    configured = yara_feed.configured_feeds()
    states = (await db.execute(select(YaraFeedState).order_by(YaraFeedState.id))).scalars().all()
    by_url = {s.url: s for s in states}
    sources = []
    seen = set()
    for url in configured:
        seen.add(url)
        state = by_url.get(url)
        sources.append({
            "url": yara_feed.redact_url(url),
            "configured": True,
            "feed_id": state.feed_id if state else None,
            "key_id": state.key_id if state else None,
            "last_checked_at": state.last_checked_at.isoformat() if state and state.last_checked_at else None,
            "last_success_at": state.last_success_at.isoformat() if state and state.last_success_at else None,
            "last_error": state.last_error if state else None,
            "bundle_version": state.bundle_version if state else None,
            "rules_count": state.rules_count if state else 0,
        })
    # Uno stato rimasto da una configurazione precedente è utile per capire
    # perché la UI mostra regole che il feed attuale non elenca più.
    for state in states:
        if state.url in seen:
            continue
        sources.append({
            "url": yara_feed.redact_url(state.url),
            "configured": False,
            "feed_id": state.feed_id,
            "key_id": state.key_id,
            "last_checked_at": state.last_checked_at.isoformat() if state.last_checked_at else None,
            "last_success_at": state.last_success_at.isoformat() if state.last_success_at else None,
            "last_error": state.last_error,
            "bundle_version": state.bundle_version,
            "rules_count": state.rules_count,
        })
    return {
        "enabled": settings.YARA_FEED_ENABLED,
        "auto_sync": settings.YARA_FEED_ENABLED,
        "interval_s": settings.YARA_FEED_INTERVAL_S,
        "signature_required": True,
        "key_id": settings.YARA_FEED_KEY_ID or None,
        "key_fingerprint": yara_feed.key_fingerprint(),
        "sources": sources,
    }


@router.post("/feeds/sync")
async def sync_feeds(request: Request, db: AsyncSession = Depends(get_db),
                     user=Depends(require_perm("manage"))):
    """Force a checked sync now. Never accepts a URL or unsigned content."""
    if not settings.YARA_FEED_ENABLED:
        raise HTTPException(status_code=409, detail="YARA feeds are disabled by configuration")
    result = await yara_feed.sync_all_feeds()
    await log_audit(db, action="yara_feed_manual_sync", resource="yara_feed",
                    details={"ok": result.get("ok"), "results": [
                        {"url": r.get("url"), "ok": r.get("ok"), "error": r.get("error")}
                        for r in result.get("results", [])
                    ]}, user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return result


@router.get("/rules")
async def list_rules(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    result = await db.execute(select(YaraRule).order_by(YaraRule.id.desc()))
    rules = result.scalars().all()
    return {"items": [_rule_view(r) for r in rules]}


@router.post("/rules")
async def create_rule(payload: YaraRuleCreate, request: Request,
                      db: AsyncSession = Depends(get_db),
                      user=Depends(require_perm("rules"))):
    _validate_rule_content(payload.content)
    existing = (await db.execute(select(YaraRule).where(YaraRule.name == payload.name))).scalars().first()
    if existing:
        raise HTTPException(status_code=409, detail="A YARA rule with this name already exists")
    tags = _clean_tags(payload.tags)
    rule = YaraRule(
        name=payload.name, content=payload.content, is_active=payload.is_active,
        severity=payload.severity, description=payload.description, tags=tags,
        mitre_technique_id=payload.mitre_technique_id,
        source="manual", managed=False,
        checksum=hashlib.sha256(payload.content.encode("utf-8")).hexdigest(),
        created_by=user.id,
    )
    db.add(rule)
    await log_audit(db, action="yara_rule_create", resource=f"yara_rule:{payload.name}",
                    details={"active": payload.is_active, "severity": payload.severity},
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return _rule_view(rule)


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: int, payload: YaraRuleUpdate, request: Request,
                      db: AsyncSession = Depends(get_db),
                      user=Depends(require_perm("rules"))):
    result = await db.execute(select(YaraRule).where(YaraRule.id == rule_id))
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    if rule.managed:
        editable = [payload.name, payload.content, payload.severity, payload.description,
                    payload.tags, payload.mitre_technique_id]
        if any(value is not None for value in editable):
            raise HTTPException(
                status_code=409,
                detail="Feed-managed rule: update the signed feed; only is_active can be changed here",
            )
    if payload.name is not None:
        duplicate = (await db.execute(select(YaraRule).where(
            YaraRule.name == payload.name, YaraRule.id != rule_id))).scalars().first()
        if duplicate:
            raise HTTPException(status_code=409, detail="A YARA rule with this name already exists")
        rule.name = payload.name
    if payload.content is not None:
        _validate_rule_content(payload.content)
        rule.content = payload.content
        rule.checksum = hashlib.sha256(payload.content.encode("utf-8")).hexdigest()
    if payload.is_active is not None:
        rule.is_active = payload.is_active
    if payload.severity is not None:
        rule.severity = payload.severity
    if payload.description is not None:
        rule.description = payload.description
    if payload.tags is not None:
        rule.tags = _clean_tags(payload.tags) or []
    if payload.mitre_technique_id is not None:
        rule.mitre_technique_id = payload.mitre_technique_id
    await log_audit(db, action="yara_rule_update", resource=f"yara_rule:{rule_id}",
                    details={"active": rule.is_active, "managed": rule.managed},
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return _rule_view(rule)


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: int, request: Request,
                      db: AsyncSession = Depends(get_db),
                      user=Depends(require_perm("rules"))):
    result = await db.execute(select(YaraRule).where(YaraRule.id == rule_id))
    rule = result.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    if rule.managed:
        raise HTTPException(
            status_code=409,
            detail="Feed-managed rule: remove it from the signed feed instead of deleting it here",
        )
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

    # Il tetto resta: un feed grande non deve trasformare un singolo comando
    # in un payload arbitrario. L'analista può selezionare rule_ids.
    selected = rules[:MAX_RULES_PER_SCAN]
    rules_yara = "\n\n".join(r.content for r in selected)
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
                             "rules": [r.id for r in selected]},
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return {"queued": True, "agent_id": str(agent.agent_id),
            "rules_sent": len(selected),
            "note": "Matches will arrive as 'yara_match' alerts and are searchable in Log Search"}
