import time
from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel
from app.database.connection import get_db
from app.database.models import CustomRule
from app.core.deps import get_current_user
from app.rules.rule_definitions import STATIC_RULES, ALL_RULES, EventSchema

from app.rules.heuristic_engine import HeuristicEngine
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter(tags=["Rules Engine"])

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
    pattern: str = ""
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
    name: str
    severity: str
    description: str
    mitre_tactic_id: Optional[str] = None
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_id: str

class RuleTestRequest(BaseModel):
    event: Dict[str, Any]

class RuleTestResult(BaseModel):
    matched: bool
    severity: str = "LOW"
    description: str = ""
    rule_name: str = ""
    mitre_technique_id: Optional[str] = None

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
            name=s.name, severity=s.severity, description=s.description,
            mitre_tactic=s.mitre_tactic, mitre_technique=s.mitre_technique,
            mitre_technique_id=s.mitre_technique_id
        )
        for s in STATIC_RULES
    ]

@router.post("/test", response_model=List[RuleTestResult])
async def test_rule(payload: RuleTestRequest, db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    event = EventSchema(**payload.event)
    results = []

    for rule_fn in ALL_RULES:
        try:
            r = rule_fn(event)
            if r.triggered:
                results.append(RuleTestResult(
                    matched=True, severity=r.severity, description=r.description,
                    rule_name=rule_fn.__name__, mitre_technique_id=r.mitre_technique_id
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

@router.post("/", response_model=RuleOut)
async def create_rule(rule: RuleCreate, db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    if rule.severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        raise HTTPException(status_code=400, detail="Invalid severity level")
    db_rule = CustomRule(**rule.model_dump())
    db.add(db_rule)
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
async def update_rule(rule_id: int, updates: Dict[str, Any] = Body(...), db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    rule = await db.get(CustomRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    for key, value in updates.items():
        if hasattr(rule, key):
            setattr(rule, key, value)
    await db.commit()
    await db.refresh(rule)
    _invalidate_rules_cache()
    return rule

@router.delete("/{rule_id}")
async def delete_rule(rule_id: int, db: AsyncSession = Depends(get_db), current_user = Depends(get_current_user)):
    rule = await db.get(CustomRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
    return {"status": "deleted"}
