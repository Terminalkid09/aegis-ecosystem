"""ATT&CK coverage built from the same engines that evaluate alerts."""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query

from app.core.deps import get_current_user
from app.rules.rule_definitions import STATIC_RULES
from app.rules.sigma import get_engine as get_sigma_engine
from app.services.correlation import get_correlation_engine

router = APIRouter(tags=["Detections"])

_PRODUCT_PLATFORM = {
    "windows": "windows", "linux": "linux", "macos": "macos",
    "zeek": "network", "suricata": "network", "firewall": "network",
    "proxy": "network", "webserver": "network", "kraken": "deception",
}


def _platform_for(logsource: Dict[str, Any]) -> str:
    product = str((logsource or {}).get("product") or "").lower()
    return _PRODUCT_PLATFORM.get(product, "other")


def coverage(platform: Optional[str] = None) -> Dict[str, Any]:
    sigma = get_sigma_engine()
    correlation = get_correlation_engine()
    grouped: Dict[str, Dict[str, Any]] = {}

    def add(tech_id: str, technique: str, tactic: str, platform_name: str,
            rule_id: str, title: str, engine: str):
        key = tech_id or "UNMAPPED"
        entry = grouped.setdefault(key, {
            "technique_id": key, "technique": technique or key,
            "tactic": tactic or "unknown", "platforms": set(),
            "rules": [], "covered": False,
        })
        entry["platforms"].add(platform_name)
        entry["rules"].append({"id": rule_id, "title": title, "engine": engine})
        entry["covered"] = True

    for rule in STATIC_RULES:
        add(rule.mitre_technique_id, rule.mitre_technique, rule.mitre_tactic,
            "endpoint", rule.rule_id, rule.name, "static")
    for rule in sigma.executable_rules():
        platform_name = _platform_for(rule.logsource)
        for technique in rule.mitre_techniques() or ["UNMAPPED"]:
            add(technique, technique, "sigma", platform_name,
                rule.id, rule.title, "sigma")
    for rule in correlation.rules():
        if not rule.executable:
            continue
        for technique in rule.mitre or ["UNMAPPED"]:
            add(technique, technique, "correlation", "network",
                rule.id, rule.title, "correlation")

    items = []
    for entry in grouped.values():
        entry["platforms"] = sorted(entry["platforms"])
        if platform and platform not in entry["platforms"]:
            continue
        items.append(entry)
    items.sort(key=lambda item: item["technique_id"])
    return {
        "platform": platform or "all",
        "items": items,
        "techniques_covered": len([i for i in items if i["covered"] and i["technique_id"] != "UNMAPPED"]),
        "rules_total": sum(len(i["rules"]) for i in items),
        "engines": {"sigma": sigma.coverage(), "correlation": correlation.coverage()},
        "platforms": ["all", "windows", "linux", "macos", "network", "deception", "endpoint", "other"],
    }


@router.get("/coverage")
async def attack_coverage(
    platform: Optional[str] = Query(None, max_length=32),
    _user=Depends(get_current_user),
):
    return coverage(platform)
