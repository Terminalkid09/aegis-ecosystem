"""M5 Fase 6: grouping, beacon, trigger-match e dry-run metadata (senza DB)."""
from app.services.incident_grouping import (
    group_key, suggest_groups, group_title, beacon_verdict,
)
from app.services.playbook_engine import describe_action, _matches_trigger
from app.database.models import Playbook, Alert


def _alert(**kw):
    base = {"agent_id": "a1", "mitre_technique_id": "T1204",
            "process_name": "powershell.exe",
            "timestamp": "2026-09-01T10:00:00+00:00"}
    base.update(kw)
    return base


def test_group_key_buckets_similar():
    a = _alert()
    b = _alert(timestamp="2026-09-01T10:20:00+00:00")
    c = _alert(timestamp="2026-09-01T12:00:00+00:00")
    assert group_key(a) == group_key(b), "stessa finestra 30m"
    assert group_key(a) != group_key(c), "finestre diverse"
    assert group_key(a) != group_key(_alert(mitre_technique_id="T1059"))
    assert group_key(a) != group_key(_alert(process_name="cmd.exe"))
    assert group_key(a) != group_key(_alert(agent_id="a2"))


def test_group_key_case_and_path_insensitive():
    a = _alert(process_name="C:\\Windows\\System32\\CMD.EXE")
    b = _alert(process_name="cmd.exe")
    assert group_key(a)[:3] == group_key(b)[:3]


def test_group_key_missing_timestamp_stable():
    a = _alert()
    del a["timestamp"]
    assert group_key(a) == group_key(dict(a))


def test_suggest_groups_clusters():
    alerts = [_alert(), _alert(timestamp="2026-09-01T10:10:00+00:00"),
              _alert(mitre_technique_id="T1059"),
              _alert(agent_id="a2")]
    groups = suggest_groups(alerts)
    assert len(groups) == 3
    assert sorted(len(v) for v in groups.values()) == [1, 1, 2]


def test_group_title_readable():
    key = ("a1", "T1204", "powershell.exe", 5)
    assert "T1204" in group_title(key, "ws-01") and "ws-01" in group_title(key, "ws-01")


def test_beacon_verdict_regular():
    ts = [1000.0, 1060.0, 1120.0, 1180.0, 1240.0]
    v = beacon_verdict(ts)
    assert v["beacon"] is True
    assert abs(v["avg_interval"] - 60.0) < 1e-6
    assert v["variance"] < 5.0


def test_beacon_verdict_irregular_and_few():
    assert beacon_verdict([1.0, 2.0, 100.0, 101.0, 500.0])["beacon"] is False
    assert beacon_verdict([1.0, 2.0])["reason"] == "too-few-samples"
    assert beacon_verdict([])["reason"] == "too-few-samples"


def test_matches_trigger_pure():
    p = Playbook(name="x", trigger_severity="HIGH",
                 trigger_event_type="PROCESS_CREATED",
                 trigger_process_name="powershell")
    a = Alert(agent_id="00000000-0000-0000-0000-000000000000",
              severity="HIGH", process_name="powershell.exe",
              event_type="PROCESS_CREATED", description="d")
    assert _matches_trigger(p, a) is True
    p.trigger_severity = "LOW"
    assert _matches_trigger(p, a) is False


def test_describe_action_known_and_unknown():
    d = describe_action("isolate_host")
    assert d["risk"] == "critical" and d["approver"] == "analyst"
    assert d["reversible"] is True and "rollback" in d
    assert describe_action("script")["approver"] == "admin"
    assert describe_action("collect_ioc")["risk"] == "low"
    u = describe_action("teleport_host")
    assert u["risk"] == "critical" and u["approver"] == "admin"
