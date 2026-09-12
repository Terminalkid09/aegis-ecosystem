import pytest
from pydantic import ValidationError
from app.api.schemas.common import EventSchema
from app.core.redaction import redact_text


def test_incomplete_event_missing_required_rejected():
    with pytest.raises(ValidationError):
        EventSchema.model_validate({"event_type": "PROCESS_CREATED"})


def test_incomplete_event_missing_required_agent_id_rejected():
    with pytest.raises(ValidationError):
        EventSchema.model_validate({"timestamp": "2026-01-01T00:00:00Z", "event_type": "X"})


def test_corrupted_command_line_too_long_rejected():
    with pytest.raises(ValidationError):
        EventSchema.model_validate({
            "agentId": "a" * 65,
            "timestamp": "2026-01-01T00:00:00Z",
            "eventType": "PROCESS_CREATED",
            "commandLine": "x" * 4097,
        })


def test_legacy_v1_event_accepts_optional_v2_fields():
    ev = EventSchema.model_validate({
        "agent_id": "agent-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "event_type": "PROCESS_CREATED",
        "pid": 1,
    })
    assert ev.event_id is None  # compat backward: v1 senza event_id è valido


def test_camel_alias_backward_compat():
    ev = EventSchema.model_validate({
        "agentId": "agent-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "eventType": "X",
        "parentPid": 2,
        "commandLine": "--x",
    })
    assert ev.parent_pid == 2
    assert ev.command_line == "--x"


def test_future_unknown_fields_dropped_not_crash():
    ev = EventSchema.model_validate({
        "agent_id": "agent-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "event_type": "X",
        "some_future_field": {"nested": 1},
    })
    assert ev.event_type == "X"


def test_bad_timestamp_rejected():
    with pytest.raises(ValidationError):
        EventSchema.model_validate({
            "agent_id": "a",
            "timestamp": "not-a-date",
            "event_type": "X",
        })


def test_negative_seq_rejected():
    with pytest.raises(ValidationError):
        EventSchema.model_validate({
            "agent_id": "a",
            "timestamp": "2026-01-01T00:00:00Z",
            "event_type": "X",
            "seq": -5,
        })