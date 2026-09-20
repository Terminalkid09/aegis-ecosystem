import pytest
from app.rules.rule_definitions import STATIC_RULES, RULE_BY_FN, rule_catalog, rule_exceptions, rule_allowlist

REQUIRED_ATTRS = ("rule_id", "name", "version", "confidence", "severity", "description",
                  "mitre_tactic_id", "mitre_tactic", "mitre_technique_id", "mitre_technique")


def test_every_static_rule_has_full_metadata():
    for s in STATIC_RULES:
        assert s.rule_id.startswith("AEGIS-"), s.rule_id
        for attr in REQUIRED_ATTRS:
            assert getattr(s, attr) not in (None, ""), f"{s.rule_id} manca {attr}"


def test_rule_ids_unique():
    ids = [s.rule_id for s in STATIC_RULES]
    assert len(ids) == len(set(ids))


def test_all_rules_registered_for_stamping():
    from app.rules.rule_definitions import ALL_RULES
    assert len(RULE_BY_FN) == len(ALL_RULES) == len(STATIC_RULES)


def test_every_rule_has_exceptions_and_allowlist_doc():
    for s in STATIC_RULES:
        assert rule_exceptions(s.rule_id), f"{s.rule_id} senza eccezioni documentate"
        assert rule_allowlist(s.rule_id), f"{s.rule_id} senza allowlist documentata"


def test_rule_catalog_is_ui_ready():
    cat = rule_catalog()
    assert len(cat) == len(STATIC_RULES)
    for item in cat:
        assert "name" in item and "mitre_technique_id" in item
        assert isinstance(item["exceptions"], list)
        assert isinstance(item["allowlist"], list)