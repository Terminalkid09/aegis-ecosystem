from datetime import datetime, timezone
from types import SimpleNamespace

from app.schemas.schemas import SensorEventIn
from app.services.aegis_ingest import build_attack_payload


def _event():
    return SimpleNamespace(
        session_id="sess-0001",
        attacker_ip="45.9.20.7",
        attacker_port=51244,
        sensor_type="ssh",
        sensor_port=22,
        timestamp_start=datetime.now(timezone.utc),
        country="RU",
        city="Moscow",
        asn=49505,
        is_known_threat=True,
        commands=[SimpleNamespace(command="uname -a")],
        malware_samples=[],
    )


def test_wire_payload_has_no_password():
    payload = SensorEventIn(
        sensor_type="ssh", attacker_ip="45.9.20.7",
        attacker_port=51244, sensor_port=22, session_id="sess-0001",
        username="root", password="must-not-leave-kraken",
    )
    wire = build_attack_payload(_event(), payload)
    serialized = str(wire)
    assert "must-not-leave-kraken" not in serialized
    assert "password" not in serialized
    assert wire["events"][0]["source"] == "kraken"
    assert wire["events"][0]["network"]["src_ip"] == "45.9.20.7"


def test_lab_context_is_not_flattened_to_sensor():
    payload = SensorEventIn(
        sensor_type="ssh", attacker_ip="45.9.20.7",
        attacker_port=51244, sensor_port=22, session_id="sess-lab-001",
        context="lab", run_id="run-4.2", scenario_id="scn-ssh",
        topology_id="topo-lab",
    )
    wire = build_attack_payload(_event(), payload)
    raw = wire["events"][0]["raw"]
    assert raw["context"] == "lab"
    assert raw["run_id"] == "run-4.2"
    assert raw["scenario_id"] == "scn-ssh"
    assert raw["topology_id"] == "topo-lab"


def test_wire_event_id_is_stable():
    payload = SensorEventIn(
        sensor_type="ssh", attacker_ip="45.9.20.7",
        attacker_port=51244, sensor_port=22, session_id="sess-0001",
    )
    first = build_attack_payload(_event(), payload)
    second = build_attack_payload(_event(), payload)
    assert first["events"][0]["event_id"] == second["events"][0]["event_id"]
