from __future__ import annotations

import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[2] / "rdp" / "log_shipper.py"
spec = importlib.util.spec_from_file_location("rdp_log_shipper", MODULE_PATH)
assert spec and spec.loader
shipper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shipper)


def test_parse_pam_failed_login():
    record = shipper.parse_log_line(
        "Nov 21 17:00:00 host sshd[1]: Failed password for administrator "
        "from 203.0.113.9 port 4444 ssh2"
    )
    assert record is not None
    assert record["attacker_ip"] == "203.0.113.9"
    assert record["attacker_port"] == 4444
    assert record["username"] == "administrator"
    assert record["result"] == "failed"


def test_parse_pam_accepted_login():
    record = shipper.parse_log_line(
        "Nov 21 17:00:00 host sshd[1]: Accepted password for admin "
        "from 198.51.100.7 port 5555 ssh2"
    )
    assert record is not None
    assert record["result"] == "success"
    assert record["username"] == "admin"


def test_parse_xrdp_connection_without_credentials():
    record = shipper.parse_log_line(
        "[20261121-17:00:00] [INFO ] Socket 12: AF_INET6 connection received "
        "from ::ffff:192.0.2.10 port 33333"
    )
    assert record is not None
    assert record["result"] == "connection"
    assert record["username"] is None
    assert record["attacker_ip"] == "::ffff:192.0.2.10"


def test_build_event_never_contains_password_and_is_bounded():
    record = shipper.parse_log_line(
        "Failed password for kraken from 203.0.113.50 port 2222 ssh2"
    )
    event = shipper.build_event(record, sensor_port=3389)
    assert event is not None
    assert event["sensor_type"] == "rdp"
    assert event["sensor_port"] == 3389
    assert event["attacker_port"] == 2222
    assert event["session_id"].startswith("rdp-")
    assert "password" not in event
    assert event["commands"] == ["RDP authentication failed"]


def test_invalid_ip_is_rejected():
    record = shipper.parse_log_line(
        "Failed password for x from not-an-ip port 2222 ssh2"
    )
    assert record is None
    assert shipper.build_event({"attacker_ip": "not-an-ip"}) is None
