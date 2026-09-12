"""M1 Fase 2: schema v2 accettato e backward-compat + dedup/seq (tutto senza DB)."""
from datetime import datetime, timezone

from app.api.schemas.common import EventSchema, StatsResponse
from app.services.event_dedup import EventDedup, SeqTracker


def _v1():
    return {
        "agent_id": "agent-001",
        "timestamp": datetime.now(timezone.utc),
        "event_type": "PROCESS_CREATED",
        "pid": 101,
        "process_name": "echo",
    }


def _v2():
    d = _v1()
    d.update({
        "eventId": "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
        "schemaVersion": 2,
        "bootId": "boot-9",
        "seq": 41,
        "tsMonotonicNs": 111,
        "tsWallNs": 222,
        "procStartNs": 100,
        "sessionId": "tty1",
        "integrityLevel": "high",
        "proto": "tcp",
        "direction": "outbound",
        "provenance": "ebpf-full",
        "quality": "full",
    })
    return d


def test_event_schema_accepts_v1_legacy():
    e = EventSchema(**_v1())
    assert e.event_id is None
    assert e.seq is None


def test_event_schema_accepts_v2_camel_case():
    e = EventSchema(**_v2())
    assert e.event_id == "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
    assert e.schema_version == 2
    assert e.boot_id == "boot-9"
    assert e.seq == 41
    assert e.ts_monotonic_ns == 111
    assert e.ts_wall_ns == 222
    assert e.proc_start_ns == 100
    assert e.provenance == "ebpf-full"


def test_event_schema_accepts_snake_case():
    d = _v1()
    d["event_id"] = "x"
    assert EventSchema(**d).event_id == "x"


def test_event_schema_clock_drift_never_rejects():
    # Wall-clock impazzito (2036 o 1970) + monotonico fermo: accettato,
    # la correlazione usa il monotonico (documentato in EVENT_SCHEMA_V2).
    d = _v2()
    d["timestamp"] = datetime(2036, 1, 1, tzinfo=timezone.utc)
    d["tsMonotonicNs"] = 0
    assert EventSchema(**d).ts_monotonic_ns == 0


def test_dedup_duplicate_and_lru():
    dd = EventDedup(capacity=2)
    assert dd.check("a", "1") is False
    assert dd.check("a", "1") is True
    assert dd.check("a", None) is False
    dd.check("a", "2")
    dd.check("a", "3")  # sfratta "1"
    assert dd.check("a", "1") is False
    assert dd.duplicates == 1


def test_seq_gaps_resets_late():
    st = SeqTracker()
    assert st.observe("a", "b1", 0)["gap"] == 0
    assert st.observe("a", "b1", 1)["gap"] == 0
    assert st.observe("a", "b1", 4)["gap"] == 2
    assert st.observe("a", "b1", 2)["late"] is True
    assert st.observe("a", "b2", 0)["reset"] is True
    assert st.observe("a", "b1", None) == {"tracked": False}
    snap = st.snapshot()
    assert snap["gaps"] == 1 and snap["gap_events"] == 2
    assert snap["resets"] == 1 and snap["late"] == 1


def test_stats_response_has_pipeline_counters():
    s = StatsResponse(total_alerts=0, unresolved_alerts=0, active_agents=0)
    assert s.events_duplicated == 0
    assert s.events_seq_gaps == 0
    assert s.events_seq_gap_events == 0
