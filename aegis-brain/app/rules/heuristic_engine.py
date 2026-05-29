from typing import Optional, Any
from app.rules.rule_definitions import ALL_RULES, RuleResult
from app.core.logging import get_logger

logger = get_logger(__name__)

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

class HeuristicEngine:
    def analyze(self, event: Any) -> AnalysisResult:
        result = AnalysisResult()
        triggered_rules: list[RuleResult] = []

        for rule in ALL_RULES:
            try:
                rule_result = rule(event)
                if rule_result.triggered:
                    triggered_rules.append(rule_result)
            except Exception as e:
                logger.error("Error in rule '%s': %s", rule.__name__, str(e))

        if not triggered_rules:
            return result

        worst = max(triggered_rules, key=lambda r: SEVERITY_WEIGHT.get(r.severity, 0))
        result.is_threat   = True
        result.severity    = worst.severity
        result.description = worst.description
        result.rule_count  = len(triggered_rules)

        logger.info("THREAT DETECTED: %s | severity=%s", event.process_name, result.severity)
        return result
