import pytest
from app.core.redaction import redact_text, redact_value, sanitize_event


def test_redact_password_equals():
    assert "password=<redacted>" in redact_text("prog.py --password=hunter2 run")


def test_redact_bearer_header_in_cmdline():
    out = redact_text('curl -H "Authorization: Bearer xyz.abc" https://x')
    assert "xyz.abc" not in out


def test_redact_aws_access_key_pattern():
    sample = "AKIA" + "ABCDEFGHIJKLMNOP"
    assert sample not in redact_text(f"export AWS_ACCESS_KEY_ID={sample}")


def test_redact_secret_equals_in_json_style():
    out = redact_text('"token": "abcdef123456"')
    assert "abcdef123456" not in out


def test_redact_env_assignment_windows():
    out = redact_text("set AEGIS_TOKEN=supersecretvalue")
    assert "supersecretvalue" not in out


def test_redact_value_by_key():
    assert redact_value("apiKey", "12345-abcd") == "<redacted>"
    assert redact_value("hostname", "box-01") == "box-01"


def test_redact_length_bounded():
    long = "x" * 10000
    assert len(redact_text(long)) <= 4096


def test_sanitize_event_redacts_command_line():
    payload = {"command_line": "--token=hunter2 run", "process_name": "a.exe", "user": "bob"}
    out = sanitize_event(payload)
    assert "hunter2" not in out["command_line"]
    assert out["process_name"] == "a.exe"


def test_redact_null_passthrough():
    assert redact_text(None) is None


# --- caratteri di controllo non memorizzabili (audit: NUL byte) -------------


def test_nul_byte_removed_from_every_string():
    """Un NUL non ha rappresentazione in una colonna text: si toglie.

    Non è cosmetico: PostgreSQL rifiuta 0x00 ('invalid byte sequence for
    encoding "UTF8: 0x00"'), quindi un evento con un NUL non era sporco, era
    non scrivibile — e quell'errore, lungo l'ingestion, diventava un 500.
    """
    out = sanitize_event({
        "process_name": "robust\x00.exe",
        "parent_process_name": "explorer\x00.exe",  # campo passthrough
        "hostname": "host\x00-01",
        "command_line": "run \x00 --flag",
    })
    assert out["process_name"] == "robust.exe"
    assert out["parent_process_name"] == "explorer.exe"
    assert out["hostname"] == "host-01"
    assert "\x00" not in out["command_line"]


def test_nul_byte_removed_in_nested_structures():
    out = sanitize_event({
        "process_name": "a.exe",
        "processes": [{"name": "b\x00.exe"}],
        "network_flows": [{"dst": "1\x002.3.4"}],
    })
    assert out["processes"][0]["name"] == "b.exe"
    assert out["network_flows"][0]["dst"] == "12.3.4"


def test_removal_is_declared_in_quality():
    """La perdita si dichiara: un evento alterato deve essere riconoscibile."""
    out = sanitize_event({"process_name": "a\x00.exe"})
    assert "stripped-ctrl" in (out.get("quality") or "")


def test_clean_event_has_no_quality_marker():
    """Controprova: senza caratteri da togliere, `quality` non si inventa nulla."""
    out = sanitize_event({"process_name": "a.exe", "command_line": "echo ok"})
    assert not out.get("quality")


def test_tab_and_newline_are_legitimate():
    """TAB/LF/CR restano: sono normali in una command line e nei log."""
    cmd = "prog.exe\t-a\n-b\r\n"
    out = sanitize_event({"command_line": cmd})
    assert out["command_line"] == cmd
    assert not out.get("quality")
