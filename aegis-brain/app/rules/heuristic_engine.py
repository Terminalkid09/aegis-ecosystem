from typing import Optional, Any, Dict, List
import re
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.database.models import CustomRule
from app.rules.rule_definitions import ALL_RULES, STATIC_RULES, RuleResult
from app.core.logging import get_logger

logger = get_logger(__name__)

# Process names that should NEVER trigger alerts (legitimate system/third-party processes)
ALWAYS_ALLOW_PROCESS_NAMES = {
    "updater.exe", "update.exe", "chrome_updater.exe", "firefox_updater.exe",
    "msedge_updater.exe", "brave_updater.exe", "opera_autoupdate.exe",
    "sophosupdate.exe", "sophosupdater.exe",
}

SEVERITY_WEIGHT = {
    "LOW":      1,
    "MEDIUM":   2,
    "HIGH":     3,
    "CRITICAL": 4,
}

class AnalysisResult:
    def __init__(self):
        self.is_threat: bool = False
        self.severity: str = "LOW"
        self.description: str = ""
        self.rule_count: int = 0
        self.mitre_tactic: Optional[str] = None
        self.mitre_technique: Optional[str] = None
        self.mitre_technique_id: Optional[str] = None
        self.triggered_rules: list = []
        self.auto_remediation: Optional[str] = None

def _check_whitelist(rule: CustomRule, hostname: Optional[str], ip: Optional[str]) -> bool:
    if not rule.whitelist:
        return True
    whitelist = rule.whitelist
    if isinstance(whitelist, dict):
        excluded_hostnames = whitelist.get("hostnames", [])
        excluded_ips = whitelist.get("ips", [])
        if hostname and hostname in excluded_hostnames:
            return False
        if ip and ip in excluded_ips:
            return False
    return True

def _match_event_field(event: Any, field: str) -> Optional[str]:
    return getattr(event, field, None) or getattr(event, field.lower(), None)

def _eval_condition(event: Any, cond: Dict) -> bool:
    field = cond.get("target_field", "")
    pattern = cond.get("pattern", "")
    operator = cond.get("operator", "regex")
    value = _match_event_field(event, field)
    if value is None or not isinstance(value, str):
        return False
    if operator == "regex":
        try:
            return bool(re.search(pattern, value, re.IGNORECASE))
        except re.error:
            return False
    elif operator == "equals":
        return value.lower() == pattern.lower()
    elif operator == "contains":
        return pattern.lower() in value.lower()
    elif operator == "not_equals":
        return value.lower() != pattern.lower()
    return False

class HeuristicEngine:
    async def analyze(self, event: Any, db: Optional[AsyncSession] = None) -> AnalysisResult:
        result = AnalysisResult()
        triggered_rules: list[RuleResult] = []
        auto_remediation: Optional[str] = None

        # Skip analysis for known legitimate processes
        proc_name = getattr(event, "process_name", None) or getattr(event, "name", None)
        if proc_name and proc_name.lower().strip() in ALWAYS_ALLOW_PROCESS_NAMES:
            return result

        # 1. Evaluate Static Definitions
        for rule_fn in ALL_RULES:
            try:
                rule_result = rule_fn(event)
                if rule_result.triggered:
                    triggered_rules.append(rule_result)
            except Exception as e:
                logger.error("Error in static rule: %s", str(e))

        # 2. Evaluate Dynamic Database Rules (skip if no db session)
        if db is not None:
            try:
                custom_rules_result = await db.execute(select(CustomRule).where(CustomRule.is_active == True))
                custom_rules = custom_rules_result.scalars().all()

                for crule in custom_rules:
                    try:
                        if not _check_whitelist(crule, getattr(event, "hostname", None), getattr(event, "ip_address", None)):
                            continue

                        matched = False
                        conditions = crule.conditions

                        if conditions and isinstance(conditions, dict):
                            logic = conditions.get("logic", "and")
                            items = conditions.get("conditions", [])
                            if logic == "or":
                                matched = any(_eval_condition(event, c) for c in items)
                            else:
                                matched = all(_eval_condition(event, c) for c in items)
                        else:
                            # Single-field fallback
                            field_val = getattr(event, crule.target_field, None)
                            if field_val and isinstance(field_val, str):
                                matched = bool(re.search(crule.pattern, field_val, re.IGNORECASE))

                        if matched:
                            triggered_rules.append(RuleResult(
                                triggered=True,
                                severity=crule.severity,
                                description=f"[CUSTOM RULE: {crule.name}] Match on {crule.target_field}='{getattr(event, crule.target_field, '')}'",
                                mitre_tactic=crule.mitre_tactic,
                                mitre_technique=crule.mitre_technique,
                                mitre_technique_id=crule.mitre_technique_id,
                            ))

                            # Update counter
                            now = datetime.now(timezone.utc)
                            await db.execute(
                                update(CustomRule)
                                .where(CustomRule.id == crule.id)
                                .values(trigger_count=CustomRule.trigger_count + 1, last_triggered=now)
                            )

                            if crule.auto_remediation:
                                auto_remediation = crule.auto_remediation

                    except Exception as e:
                        logger.error("Error evaluating custom rule '%s': %s", crule.name, str(e))

            except Exception as e:
                logger.error("Error fetching custom rules: %s", str(e))

        if not triggered_rules:
            return result

        worst = max(triggered_rules, key=lambda r: SEVERITY_WEIGHT.get(r.severity, 0))
        result.is_threat = True
        result.severity = worst.severity
        result.description = worst.description
        result.rule_count = len(triggered_rules)
        result.mitre_tactic = worst.mitre_tactic
        result.mitre_technique = worst.mitre_technique
        result.mitre_technique_id = worst.mitre_technique_id
        result.triggered_rules = triggered_rules
        result.auto_remediation = auto_remediation

        logger.info("THREAT DETECTED: %s | severity=%s | mitre=%s",
                     getattr(event, "process_name", "unknown"), result.severity, result.mitre_technique_id)
        return result
