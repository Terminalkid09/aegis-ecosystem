import pytest
from app.core.redaction import redact_text, redact_value, sanitize_event


def test_redact_password_equals():
    assert "password=<redacted>" in redact_text("prog.py --password=hunter2 run")


def test_redact_bearer_header_in_cmdline():
    out = redact_text('curl -H "Authorization: Bearer xyz.abc" https://x')
    assert "xyz.abc" not in out


def test_redact_aws_access_key_pattern():
    assert "AKIAABCDEFGHIJKLMNOP" not in redact_text("export AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP")


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