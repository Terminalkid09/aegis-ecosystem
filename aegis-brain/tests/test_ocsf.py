"""Test mapping OCSF 1.4.0 (feature di interoperabilità SIEM).

Nessun DB: le funzioni di `app.services.ocsf` sono pure. Verificano che la
conversione resti valida (class_uid/type_uid coerenti, severità e ATT&CK
mappati) e che regga input sia ORM-like sia dict.
"""
from datetime import datetime, timezone
from types import SimpleNamespace

from app.services import ocsf


def _alert(**over):
    base = dict(
        id=7, agent_id="11111111-1111-1111-1111-111111111111",
        timestamp=datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc),
        severity="HIGH", pid=1337, parent_pid=4,
        parent_process_name="services.exe", process_name="mimikatz.exe",
        process_path=r"C:\Users\bob\Downloads\mimikatz.exe",
        event_type="PROCESS_CREATED", description="Credential dumping attempt",
        is_resolved=False,
        mitre_tactic_id="TA0006", mitre_technique_id="T1003.001",
        mitre_tactic_name="Credential Access", mitre_technique_name="LSASS Memory",
    )
    base.update(over)
    return SimpleNamespace(**base)


def _agent():
    return SimpleNamespace(
        agent_id="11111111-1111-1111-1111-111111111111", hostname="win-01",
        ip_address="10.0.0.5", os_type="windows", agent_version="4.0.0",
    )


def test_severity_mapping_is_bounded():
    assert ocsf.severity_to_ocsf("CRITICAL") == 5
    assert ocsf.severity_to_ocsf("high") == 4
    assert ocsf.severity_to_ocsf("MEDIUM") == 3
    assert ocsf.severity_to_ocsf(None) == 0
    assert ocsf.severity_to_ocsf("bogus") == 0  # mai eccezione


def test_alert_becomes_detection_finding():
    o = ocsf.alert_to_ocsf(_alert(), _agent())
    assert o["class_uid"] == 2004
    assert o["class_name"] == "Detection Finding"
    assert o["category_uid"] == 2
    assert o["type_uid"] == 200401
    assert o["severity_id"] == 4 and o["severity"] == "High"
    assert o["metadata"]["version"] == ocsf.OCSF_VERSION
    assert o["metadata"]["product"]["name"] == "Aegis Brain"
    assert o["finding_info"]["uid"] == "7"
    assert o["device"]["hostname"] == "win-01"
    assert o["device"]["os"]["name"] == "Windows"
    assert o["actor"]["process"]["name"] == "mimikatz.exe"
    assert o["actor"]["process"]["pid"] == 1337
    assert o["actor"]["process"]["parent_process"]["name"] == "services.exe"
    assert o["attacks"][0]["technique"]["uid"] == "T1003.001"
    assert o["attacks"][0]["tactic"]["uid"] == "TA0006"
    assert o["unmapped"]["aegis"]["event_type"] == "PROCESS_CREATED"


def test_resolved_alert_sets_status():
    o = ocsf.alert_to_ocsf(_alert(is_resolved=True), _agent())
    assert o["status_id"] == 4 and o["status"] == "Resolved"
    o2 = ocsf.alert_to_ocsf(_alert(is_resolved=False), _agent())
    assert o2["status_id"] == 1 and o2["status"] == "New"


def test_time_is_epoch_ms_and_iso():
    o = ocsf.alert_to_ocsf(_alert(), None)
    assert isinstance(o["time"], int)
    assert o["time"] == int(datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1000)
    assert o["time_dt"].startswith("2026-09-15T12:00:00")


def test_dict_input_supported_and_missing_agent_ok():
    raw = {"id": 1, "severity": "LOW", "description": "x", "process_name": "a"}
    o = ocsf.alert_to_ocsf(raw, None)
    assert o["class_uid"] == 2004
    assert o["severity_id"] == 2
    assert o["device"] == {}
    assert "attacks" not in o


def test_process_activity_classes_and_activities():
    launch = ocsf.process_activity_to_ocsf(
        {"event_type": "PROCESS_CREATED", "process_name": "cmd.exe", "pid": 10,
         "parent_process_name": "explorer.exe", "timestamp": 1_700_000_000_000}, None)
    assert launch["class_uid"] == 1007
    assert launch["category_uid"] == 1
    assert launch["activity_id"] == 1
    assert launch["type_uid"] == 1007 * 100 + 1
    assert launch["actor"]["process"]["parent_process"]["name"] == "explorer.exe"

    term = ocsf.process_activity_to_ocsf({"event_type": "PROCESS_TERMINATED", "process_name": "x"}, None)
    assert term["activity_id"] == 2 and term["type_uid"] == 1007 * 100 + 2

    other = ocsf.process_activity_to_ocsf({"event_type": "NETWORK_CONNECT", "process_name": "x"}, None)
    assert other["activity_id"] == 6


def test_schema_description_lists_endpoints():
    s = ocsf.schema_description()
    assert s["ocsf_version"] == ocsf.OCSF_VERSION
    classes = {m["target_class_uid"] for m in s["mappings"]}
    assert classes == {2004, 1007}
