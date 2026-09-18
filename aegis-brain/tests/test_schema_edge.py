import pytest
from pydantic import ValidationError
from app.api.schemas.common import EventSchema, TRUNCATION_TAG
from app.core.redaction import redact_text


def test_incomplete_event_missing_required_rejected():
    with pytest.raises(ValidationError):
        EventSchema.model_validate({"event_type": "PROCESS_CREATED"})


def test_incomplete_event_missing_required_agent_id_rejected():
    with pytest.raises(ValidationError):
        EventSchema.model_validate({"timestamp": "2026-01-01T00:00:00Z", "event_type": "X"})


def test_long_command_line_truncated_not_rejected():
    """Contratto invertito di proposito.

    Prima un campo lungo faceva fallire la validazione e, poiché il batch
    viene convalidato in blocco, faceva rispondere 422 all'intera richiesta:
    un solo processo con una command line lunga scartava fino a 99 eventi
    sani, e l'outbox che rigiocava il batch respinto restava bloccato per
    sempre (telemetria del sensore a zero). La telemetria si tronca e si
    dichiara, non si rifiuta.
    """
    ev = EventSchema.model_validate({
        "agentId": "a" * 65,
        "timestamp": "2026-01-01T00:00:00Z",
        "eventType": "PROCESS_CREATED",
        "commandLine": "x" * 4097,
    })
    assert len(ev.command_line) == 4096
    assert len(ev.agent_id) == 64
    # La troncatura è visibile, non silenziosa.
    assert TRUNCATION_TAG in (ev.quality or "")
    assert "command_line" in (ev.quality or "")


def test_truncation_marker_joins_existing_quality():
    ev = EventSchema.model_validate({
        "agentId": "a",
        "timestamp": "2026-01-01T00:00:00Z",
        "eventType": "PROCESS_CREATED",
        "commandLine": "x" * 5000,
        "quality": "degraded:etw-disabled",
    })
    assert ev.quality.startswith("degraded:etw-disabled;truncated:")
    assert len(ev.quality) <= 64


def test_short_fields_untouched_and_quality_absent():
    """Nessuna troncatura = nessun marcatore: il campo non deve sporcarsi."""
    ev = EventSchema.model_validate({
        "agentId": "a",
        "timestamp": "2026-01-01T00:00:00Z",
        "eventType": "PROCESS_CREATED",
        "commandLine": "notepad.exe",
    })
    assert ev.command_line == "notepad.exe"
    assert ev.quality is None


def test_process_path_truncated_to_its_own_limit():
    ev = EventSchema.model_validate({
        "agentId": "a",
        "timestamp": "2026-01-01T00:00:00Z",
        "eventType": "PROCESS_CREATED",
        "processPath": "C:\\" + "a" * 2000,
    })
    assert len(ev.process_path) == 1024
    assert "process_path" in (ev.quality or "")


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