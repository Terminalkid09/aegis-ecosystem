"""M7 Fase 8: ruoli, siti, stato flotta e retention (senza DB)."""
from datetime import datetime, timedelta, timezone

from app.core.deps import has_perm, KNOWN_ROLES
from app.services.fleet import (
    normalize_site, get_site, set_site_meta, agent_status,
    retention_cutoffs, purge_statements,
    ONLINE, STALE, OFFLINE, UNKNOWN, DEFAULT_SITE,
)
from app.api.schemas.common import AgentResponse, StatsResponse


def test_role_matrix_covers_roadmap_roles():
    for role in ("admin", "analyst", "responder", "auditor", "viewer", "user"):
        assert role in KNOWN_ROLES, role
    assert has_perm("admin", "manage")
    assert has_perm("analyst", "rules") and has_perm("analyst", "deploy")
    assert has_perm("responder", "respond")
    assert not has_perm("responder", "rules")
    assert not has_perm("responder", "manage")
    assert has_perm("auditor", "audit") and has_perm("auditor", "read")
    assert not has_perm("auditor", "respond")
    assert has_perm("viewer", "read") and not has_perm("viewer", "triage")
    assert has_perm("user", "read"), "legacy user = viewer"
    assert not has_perm("ghost", "read") and not has_perm(None, "read")


def test_site_validation():
    assert normalize_site("HQ-Milano1") == "hq-milano1"
    for bad in ("", "A B", "a/b", "x" * 65, "UPPER!", "-lead"):
        try:
            normalize_site(bad)
            raise AssertionError(f"accettato: {bad!r}")
        except ValueError:
            pass


def test_site_meta_roundtrip():
    assert get_site({}) == DEFAULT_SITE
    assert get_site({"meta": None}) == DEFAULT_SITE
    assert get_site({"meta": {"site": "hq"}}) == "hq"
    assert get_site({"meta": {"site": "BAD SITE!"}}) == DEFAULT_SITE
    m = set_site_meta({"group": "g"}, "HQ")
    assert m == {"group": "g", "site": "hq"}
    try:
        set_site_meta({}, "no good!")
        raise AssertionError("sito invalido accettato")
    except ValueError:
        pass


class _A:
    def __init__(self, meta):
        self.meta = meta


def test_get_site_object_and_dict():
    assert get_site(_A({"site": "lab"})) == "lab"
    assert get_site(object()) == DEFAULT_SITE


def test_agent_status_buckets():
    now = datetime.now(timezone.utc)
    assert agent_status(now - timedelta(minutes=5), now) == ONLINE
    assert agent_status(now - timedelta(minutes=16), now) == STALE
    assert agent_status(now - timedelta(hours=25), now) == OFFLINE
    assert agent_status(None, now) == UNKNOWN
    assert agent_status("not-a-date", now) == UNKNOWN
    assert agent_status(now + timedelta(hours=1), now) == ONLINE  # skew futuro
    assert agent_status("2026-09-01T10:00:00+00:00", now) in (STALE, OFFLINE)


def test_retention_cutoffs_match_decisions():
    now = datetime(2026, 9, 11, tzinfo=timezone.utc)
    c = retention_cutoffs(now=now)
    assert (now - c["telemetry"]).days == 14
    assert (now - c["alerts"]).days == 90
    assert (now - c["audit"]).days == 365
    assert (now - c["syslog"]).days == 30
    try:
        retention_cutoffs(telemetry_days=0, now=now)
        raise AssertionError("retention 0 accettata")
    except ValueError:
        pass


def test_purge_statements_compile():
    c = retention_cutoffs(now=datetime(2026, 9, 11, tzinfo=timezone.utc))
    stmts = purge_statements(c)
    assert [t for t, _s in stmts] == ["telemetry", "alerts", "audit", "syslog"]
    for table, stmt in stmts:
        sql = str(stmt.compile(compile_kwargs={"literal_binds": True}))
        assert "DELETE" in sql.upper()


def test_agent_response_has_fleet_fields():
    r = AgentResponse(agent_id="00000000-0000-0000-0000-000000000000")
    assert r.site == "default" and r.status == "unknown" and r.capabilities is None


def test_stats_has_fleet_counters():
    s = StatsResponse(total_alerts=0, unresolved_alerts=0, active_agents=0)
    assert s.isolated_agents == 0 and s.stale_agents == 0 and s.offline_agents == 0
