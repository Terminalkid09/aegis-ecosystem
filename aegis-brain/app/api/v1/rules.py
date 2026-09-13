import time
from fastapi import APIRouter, Depends, HTTPException, status, Body, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
from app.database.connection import get_db
from app.database.models import CustomRule
from app.core.deps import get_current_user
from app.core.audit import log_audit
from app.rules.rule_definitions import (STATIC_RULES, ALL_RULES, EventSchema, stamp_result,
                                        rule_exceptions, rule_allowlist)

from app.rules.heuristic_engine import HeuristicEngine
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Rules Engine"])


def _require_rule_operator(user):
    if (user.role or "user").lower() not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Rule changes require analyst or admin role")

_rules_cache = None
_rules_cache_time = 0.0
_rules_cache_ttl = 60

def _invalidate_rules_cache():
    global _rules_cache, _rules_cache_time
    _rules_cache = None
    _rules_cache_time = 0.0

class RuleCreate(BaseModel):
    name: str
    description: str = ""
    target_field: str = "process_name"
    pattern: str = Field(default="", max_length=200)
    severity: str = "MEDIUM"
    is_active: bool = True
    mitre_tactic_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    whitelist: Optional[Dict[str, Any]] = None
    auto_remediation: Optional[str] = None

class RuleOut(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    target_field: str
    pattern: str
    severity: str
    is_active: bool
    mitre_tactic_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    whitelist: Optional[Dict[str, Any]] = None
    auto_remediation: Optional[str] = None
    trigger_count: int = 0
    last_triggered: Optional[datetime] = None

    model_config = {"from_attributes": True}

class StaticRuleOut(BaseModel):
    rule_id: str = ""
    version: str = "1.0"
    confidence: str = "medium"
    name: str
    severity: str
    description: str
    mitre_tactic_id: Optional[str] = None
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_id: str
    exceptions: List[str] = []
    allowlist: List[str] = []

class RuleTestRequest(BaseModel):
    event: Dict[str, Any]

class RuleTestResult(BaseModel):
    matched: bool
    severity: str = "LOW"
    description: str = ""
    rule_name: str = ""
    mitre_technique_id: Optional[str] = None
    rule_id: str = "custom"
    version: str = "1.0"
    confidence: str = "medium"

@router.get("/", response_model=List[RuleOut])
async def get_rules(db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    global _rules_cache, _rules_cache_time
    now = time.monotonic()
    if now - _rules_cache_time < _rules_cache_ttl and _rules_cache:
        return _rules_cache
    result = await db.execute(select(CustomRule).order_by(CustomRule.created_at.desc()))
    rules = result.scalars().all()
    _rules_cache = rules
    _rules_cache_time = now
    return rules

@router.get("/static", response_model=List[StaticRuleOut])
async def get_static_rules(current_user = Depends(get_current_user)):
    return [
        StaticRuleOut(
            rule_id=s.rule_id, version=s.version, confidence=s.confidence,
            name=s.name, severity=s.severity, description=s.description,
            mitre_tactic=s.mitre_tactic, mitre_technique=s.mitre_technique,
            mitre_technique_id=s.mitre_technique_id,
            exceptions=list(rule_exceptions(s.rule_id)),
            allowlist=list(rule_allowlist(s.rule_id)),
        )
        for s in STATIC_RULES
    ]

@router.get("/coverage")
async def mitre_coverage(db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    """MITRE ATT&CK coverage matrix: static engine + custom rules per technique."""
    techs: Dict[str, Dict[str, Any]] = {}
    for s in STATIC_RULES:
        t = techs.setdefault(s.mitre_technique_id, {
            "technique_id": s.mitre_technique_id, "technique": s.mitre_technique,
            "tactic": s.mitre_tactic, "tactic_id": s.mitre_tactic_id,
            "static_rules": [], "custom_rules": 0,
        })
        if s.name not in t["static_rules"]:
            t["static_rules"].append(s.name)
    result = await db.execute(select(CustomRule).where(CustomRule.is_active == True))
    for r in result.scalars().all():
        tid = r.mitre_technique_id or "UNMAPPED"
        t = techs.setdefault(tid, {
            "technique_id": tid, "technique": r.mitre_technique or tid,
            "tactic": r.mitre_tactic or "unknown", "tactic_id": r.mitre_tactic_id,
            "static_rules": [], "custom_rules": 0,
        })
        t["custom_rules"] += 1
    items = sorted(techs.values(), key=lambda x: (x["technique_id"] or "~"))
    return {"techniques_covered": len([i for i in items if i["technique_id"] != "UNMAPPED"]),
            "static_rules": len(STATIC_RULES), "items": items}

@router.post("/test", response_model=List[RuleTestResult])
async def test_rule(payload: RuleTestRequest, db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    event = EventSchema(**payload.event)
    results = []

    for rule_fn in ALL_RULES:
        try:
            r = rule_fn(event)
            if r.triggered:
                stamp_result(rule_fn, r)
                results.append(RuleTestResult(
                    matched=True, severity=r.severity, description=r.description,
                    rule_name=rule_fn.__name__, mitre_technique_id=r.mitre_technique_id,
                    rule_id=r.rule_id, version=r.version, confidence=r.confidence
                ))
        except Exception as e:
            logger.error("Error testing rule %s: %s", rule_fn.__name__, str(e))

    # Also test custom rules
    try:
        custom = await db.execute(select(CustomRule).where(CustomRule.is_active == True))
        for crule in custom.scalars().all():
            try:
                field_val = getattr(event, crule.target_field, None)
                if field_val and isinstance(field_val, str):
                    import re
                    if re.search(crule.pattern, field_val, re.IGNORECASE):
                        results.append(RuleTestResult(
                            matched=True, severity=crule.severity,
                            description=f"[CUSTOM: {crule.name}] Match on {crule.target_field}",
                            rule_name=crule.name, mitre_technique_id=crule.mitre_technique_id
                        ))
            except Exception:
                pass
    except Exception:
        pass

    return results

class ReplayRequest(BaseModel):
    include_canary: bool = False
    split: str = "training"

@router.post("/replay")
async def replay_corpus(payload: ReplayRequest, current_user = Depends(get_current_user)):
    """Replay deterministico sul corpus versionato + KPI (M4 Fase 5).

    Read-only: niente DB, niente rete. Report automatico pre-release con
    precision/recall/F1 e falsi-positivi per host/giorno (assunzione
    documentata nel report). MTTD solo live (pilot).
    `split`: training (default) | validation | regression (corpora indipendenti).
    """
    from app.services.replay import score_corpus, DATASET_SPLITS
    if payload.split not in DATASET_SPLITS:
        from fastapi import HTTPException
        raise HTTPException(status_code=422, detail=f"unknown split; expected one of {list(DATASET_SPLITS)}")
    return score_corpus(include_canary=payload.include_canary, split=payload.split)

@router.post("/", response_model=RuleOut)
async def create_rule(rule: RuleCreate, request: Request, db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    _require_rule_operator(current_user)
    if rule.severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        raise HTTPException(status_code=400, detail="Invalid severity level")
    # Audit ReDoS: il pattern gira nel request-path di ingestione.
    from app.rules.heuristic_engine import is_regex_safe
    unsafe = is_regex_safe(rule.pattern)
    if unsafe:
        raise HTTPException(status_code=400, detail=f"Unsafe regex pattern: {unsafe}")
    db_rule = CustomRule(**rule.model_dump())
    db.add(db_rule)
    await db.flush()
    await log_audit(db, action="rule_create", resource="custom_rule",
                    resource_id=str(db_rule.id), details={"name": db_rule.name},
                    user_id=current_user.id, username=current_user.username,
                    ip_address=request.client.host if request.client else None)
    await db.commit()
    await db.refresh(db_rule)
    _invalidate_rules_cache()
    return db_rule

@router.get("/{rule_id}", response_model=RuleOut)
async def get_rule(rule_id: int, db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    rule = await db.get(CustomRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule

@router.patch("/{rule_id}", response_model=RuleOut)
async def update_rule(rule_id: int, updates: Dict[str, Any] = Body(...), request: Request = None, db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    _require_rule_operator(current_user)
    rule = await db.get(CustomRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    changed = {}
    for key, value in updates.items():
        if hasattr(rule, key):
            old = getattr(rule, key)
            if old != value:
                if key == "pattern":
                    from app.rules.heuristic_engine import is_regex_safe
                    unsafe = is_regex_safe(value)
                    if unsafe:
                        raise HTTPException(status_code=400, detail=f"Unsafe regex pattern: {unsafe}")
                changed[key] = {"old": old, "new": value}
            setattr(rule, key, value)
    await log_audit(db, action="rule_update", resource="custom_rule",
                    resource_id=str(rule_id), details={"changed": changed},
                    user_id=current_user.id, username=current_user.username,
                    ip_address=request.client.host if request and request.client else None)
    await db.commit()
    await db.refresh(rule)
    _invalidate_rules_cache()
    return rule

@router.delete("/{rule_id}")
async def delete_rule(rule_id: int, request: Request = None, db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    if (current_user.role or "user").lower() != "admin":
        raise HTTPException(status_code=403, detail="Deleting rules requires admin role")
    rule = await db.get(CustomRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await log_audit(db, action="rule_delete", resource="custom_rule",
                    resource_id=str(rule_id), details={"name": rule.name},
                    user_id=current_user.id, username=current_user.username,
                    ip_address=request.client.host if request and request.client else None)
    await db.delete(rule)
    await db.commit()
    return {"status": "deleted"}
