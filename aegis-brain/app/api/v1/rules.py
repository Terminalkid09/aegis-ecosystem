import time
import json
from fastapi import APIRouter, Depends, HTTPException, status, Body, Request, File, Form, UploadFile
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

# Audit L5: la cache conserva DIZIONARI serializzati, mai istanze ORM legate a
# una sessione chiusa (il vecchio global di oggetti SQLAlchemy funzionava "per
# caso" e sarebbe esploso con un DetachedInstanceError al primo refactor).
_rules_cache: Optional[List[dict]] = None
_rules_cache_time = 0.0
_rules_cache_ttl = 60

# Audit L4: allowlist dei campi modificabili via PATCH. Prima `hasattr(rule, k)`
# accettava qualunque colonna, `id` e `created_at` compresi (mass-assignment).
_RULE_UPDATABLE_FIELDS = frozenset({
    "name", "description", "target_field", "pattern", "severity", "is_active",
    "mitre_tactic_id", "mitre_tactic", "mitre_technique_id", "mitre_technique",
    "conditions", "whitelist", "auto_remediation",
})
_RULE_REQUIRED_FIELDS = frozenset({"name", "target_field", "pattern", "severity", "is_active"})
_VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


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
    if now - _rules_cache_time < _rules_cache_ttl and _rules_cache is not None:
        return _rules_cache
    result = await db.execute(select(CustomRule).order_by(CustomRule.created_at.desc()))
    _rules_cache = [RuleOut.model_validate(r).model_dump() for r in result.scalars().all()]
    _rules_cache_time = now
    return _rules_cache

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


# Audit 2026-09: il replay girava solo sul corpus sintetico interno. Un numero
# onesto di P/R/F1 richiede di poter caricare un dataset ESTERNO (Atomic Red
# Team, log convertiti in NDJSON). Questo endpoint non aggiunge regole né
# tabelle: riusa lo stesso motore deterministico dello split interno.
_IMPORT_MAX_BYTES = 32 * 1024 * 1024
_IMPORT_MAX_LINES = 50_000


async def _read_jsonl_upload(upload: UploadFile, label: str) -> List[Dict[str, Any]]:
    raw = await upload.read()
    if len(raw) > _IMPORT_MAX_BYTES:
        raise HTTPException(status_code=413,
                            detail=f"{label}: file too large (max {_IMPORT_MAX_BYTES // (1024 * 1024)} MB)")
    out: List[Dict[str, Any]] = []
    for i, line in enumerate(raw.decode("utf-8", errors="ignore").splitlines()):
        if i >= _IMPORT_MAX_LINES:
            break
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            # Le righe non-JSON nel corpus ``malformed`` sono attese: il motore
            # le conta come invalid. Negli altri split sono un errore di input.
            if label != "malformed":
                raise HTTPException(status_code=422,
                                    detail=f"{label}: line {i + 1} is not valid JSON")
            out.append(line)
    return out


@router.post("/replay/import")
async def replay_import(
    benign: Optional[UploadFile] = File(None),
    suspicious: Optional[UploadFile] = File(None),
    malformed: Optional[UploadFile] = File(None),
    host_days: float = Form(1.0),
    include_canary: bool = Form(False),
    current_user=Depends(get_current_user),
):
    """Importa un corpus esterno (JSONL) e lo scora con il motore reale.

    Formato `suspicious.jsonl`: una riga JSON = un evento Aegis, con campo
    opzionale `expect: ["AEGIS-S00X", ...]` che elenca le regole attese. Senza
    `expect` la riga è solo input (misura FP, non recall). `benign.jsonl` non
    ha `expect`. `malformed.jsonl` accetta righe rotte (devono diventare
    `invalid`, non crash).
    """
    from app.services.replay import score_corpus
    if not (benign or suspicious):
        raise HTTPException(status_code=400, detail="Provide at least benign or suspicious JSONL")
    benign_rows = await _read_jsonl_upload(benign, "benign") if benign else []
    suspicious_rows = await _read_jsonl_upload(suspicious, "suspicious") if suspicious else []
    malformed_rows: Optional[List[Any]] = \
        await _read_jsonl_upload(malformed, "malformed") if malformed else None
    report = score_corpus(
        benign=benign_rows,
        suspicious=suspicious_rows,
        malformed=malformed_rows,
        host_days=host_days if host_days > 0 else 1.0,
        include_canary=include_canary,
        split="training",
    )
    report["source"] = "external-import"
    report["imported_lines"] = {
        "benign": len(benign_rows),
        "suspicious": len(suspicious_rows),
        "malformed": len(malformed_rows) if malformed_rows is not None else None,
    }
    return report

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
    # Audit ReDoS: anche i pattern dentro `conditions` finiscono in re.search()
    # nel path di ingestione — prima erano non validati.
    for cond in (rule.conditions or {}).get("conditions", []) or []:
        if isinstance(cond, dict) and cond.get("operator", "regex") == "regex":
            unsafe_cond = is_regex_safe(str(cond.get("pattern", "")))
            if unsafe_cond:
                raise HTTPException(status_code=400,
                                    detail=f"Unsafe regex in condition: {unsafe_cond}")
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
        # Audit L4: solo campi previsti, mai id/created_at/trigger_count.
        if key not in _RULE_UPDATABLE_FIELDS:
            raise HTTPException(status_code=400, detail=f"Field not updatable: {key}")
        if value is None and key in _RULE_REQUIRED_FIELDS:
            raise HTTPException(status_code=400, detail=f"Field cannot be null: {key}")
        if key == "severity" and str(value).upper() not in _VALID_SEVERITIES:
            raise HTTPException(status_code=400, detail="Invalid severity level")
        if key == "pattern":
            # Audit ReDoS: gira nel request-path di ingestione.
            from app.rules.heuristic_engine import is_regex_safe
            unsafe = is_regex_safe(value)
            if unsafe:
                raise HTTPException(status_code=400, detail=f"Unsafe regex pattern: {unsafe}")
        if key == "conditions" and value is not None:
            for cond in (value or {}).get("conditions", []) or []:
                if isinstance(cond, dict) and cond.get("operator", "regex") == "regex":
                    from app.rules.heuristic_engine import is_regex_safe
                    unsafe = is_regex_safe(str(cond.get("pattern", "")))
                    if unsafe:
                        raise HTTPException(status_code=400,
                                            detail=f"Unsafe regex in condition: {unsafe}")
        old = getattr(rule, key, None)
        if old != value:
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
