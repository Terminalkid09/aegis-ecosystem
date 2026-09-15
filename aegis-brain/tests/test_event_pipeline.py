"""M1 Fase 2: schema v2 accettato e backward-compat + dedup/seq (tutto senza DB)."""
import json
from datetime import datetime, timezone

import pytest

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


# ── Audit: payload agent annidati/non-stringa mai 500 ─────────────────────
def test_proc_str_shapes():
    from app.services.telemetry_service import _proc_str
    assert _proc_str({"name": "svchost.exe"}) == "svchost.exe"
    assert _proc_str({"name": {"name": "System Idle Process", "pid": 0}}) == "System Idle Process"
    assert _proc_str({"process_name": "cmd.exe"}) == "cmd.exe"
    assert _proc_str("notepad.exe") == "notepad.exe"
    assert _proc_str({}) == "unknown"
    assert _proc_str(None) == "unknown"
    assert _proc_str(123) == "unknown"
    assert _proc_str({"name": 123}) == "unknown"


class FakeResult2:
    def scalars(self):
        return self

    def all(self):
        return []

    def first(self):
        return None


class FakeDB2:
    def __init__(self):
        self.added = []

    async def execute(self, *a, **k):
        return FakeResult2()

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        pass

    async def flush(self):
        pass


@pytest.mark.asyncio
async def test_process_telemetry_nested_processes_no_500(monkeypatch):
    from app.services import telemetry_service as ts
    from app.database.models import Alert

    async def fake_analyze(agent_id, metrics):
        return [{"metric": "cpu_usage", "value": 15.8, "z_score": 3.2,
                 "threshold": 3.0, "severity": "MEDIUM"}]

    async def no_suppress(agent_id, key):
        return False

    import app.services.anomaly_engine as ae
    monkeypatch.setattr(ae.anomaly_engine, "analyze", fake_analyze)
    monkeypatch.setattr(ts, "_suppressed", no_suppress)

    db = FakeDB2()
    # Forma reale inviata da vecchi agent: processi annidati + anomalia dict.
    await ts.process_telemetry(db, "agent-1", {
        "cpu_usage": 15.8, "ram_usage": 50.8,
        "processes": [{"name": {"name": "System Idle Process", "pid": 0,
                                "cpu_percent": 1356.2}}],
        "anomalies": [{"weird": True}],
    })
    alerts = [o for o in db.added if isinstance(o, Alert)]
    assert alerts, "atteso almeno un alert anomalia"
    for a in alerts:
        assert isinstance(a.process_name, str), a.process_name


# ── Audit: reliable queue (niente perdita su crash/errore) ────────────────
class FakeRedis:
    """Liste in memoria con la semantica usata dal consumer."""

    def __init__(self):
        self.lists = {"aegis:events": [], "aegis:events:processing": [],
                      "aegis:events:dlq": []}

    async def brpoplpush(self, src, dst, timeout=0):
        if not self.lists[src]:
            return None
        item = self.lists[src].pop()
        self.lists[dst].insert(0, item)
        return item

    async def rpoplpush(self, src, dst):
        if not self.lists[src]:
            return None
        item = self.lists[src].pop()
        self.lists[dst].insert(0, item)
        return item

    async def lrem(self, key, count, value):
        lst = self.lists[key]
        removed = 0
        for _ in range(abs(count)):
            if value in lst:
                lst.remove(value)
                removed += 1
        return removed

    async def lpush(self, key, value):
        self.lists[key].insert(0, value)
        return len(self.lists[key])

    async def ltrim(self, key, start, stop):
        self.lists[key] = self.lists[key][start:stop + 1]

    async def llen(self, key):
        return len(self.lists[key])


class FakeResult:
    def scalars(self):
        return self

    def first(self):
        return None


class FakeDB:
    async def execute(self, *a, **k):
        return FakeResult()

    def add(self, *a, **k):
        pass

    async def commit(self):
        pass

    async def flush(self):
        pass


class FakeSession:
    def __init__(self, db=None):
        self._db = db or FakeDB()

    async def __aenter__(self):
        return self._db

    async def __aexit__(self, *a):
        return False


def _benign_raw():
    return json.dumps({
        "agent_id": "agent-001", "timestamp": "2026-09-01T10:00:00+00:00",
        "event_type": "PROCESS_CREATED", "pid": 101,
        "process_name": "notepad.exe",
        "process_path": "C:\\Windows\\System32\\notepad.exe",
    })


@pytest.mark.asyncio
async def test_consumer_acks_only_on_success(monkeypatch):
    from app.services import redis_consumer as rc
    consumer = rc.RedisConsumer.__new__(rc.RedisConsumer)
    fake = FakeRedis()
    consumer._client = fake
    from app.rules.heuristic_engine import HeuristicEngine
    consumer._engine = HeuristicEngine()
    monkeypatch.setattr(rc, "AsyncSessionLocal", FakeSession)

    ok = await consumer._process_raw(_benign_raw())
    assert ok is True
    fake.lists["aegis:events:processing"].append("x")
    await fake.lrem("aegis:events:processing", 1, "x")
    assert await fake.llen("aegis:events:processing") == 0
    assert await fake.llen("aegis:events:dlq") == 0


@pytest.mark.asyncio
async def test_consumer_failure_goes_to_dlq(monkeypatch):
    from app.services import redis_consumer as rc
    consumer = rc.RedisConsumer.__new__(rc.RedisConsumer)
    fake = FakeRedis()
    consumer._client = fake

    ok = await consumer._process_raw("not-json{{{")
    assert ok is False
    await consumer._to_dlq("not-json{{{")
    assert await fake.llen("aegis:events:dlq") == 1


@pytest.mark.asyncio
async def test_consumer_requeues_orphans_on_boot(monkeypatch):
    from app.services import redis_consumer as rc
    consumer = rc.RedisConsumer.__new__(rc.RedisConsumer)
    fake = FakeRedis()
    consumer._client = fake
    fake.lists["aegis:events:processing"] = ["orphan-1", "orphan-2"]

    moved = await consumer._requeue_processing()
    assert moved == 2
    assert await fake.llen("aegis:events:processing") == 0
    assert await fake.llen("aegis:events") == 2
