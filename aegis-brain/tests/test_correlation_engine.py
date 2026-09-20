"""Test del motore di correlazione multi-evento (threshold + sequence).

Usa un Redis finto in memoria: la correlazione è logica di stato, non di
storage, e testarla senza infrastruttura esterna la rende eseguibile ovunque
(compresa la CI senza servizi). I casi "negativi" sono importanti quanto quelli
positivi: un motore che scatta su tutto è inutile quanto uno che non scatta mai.
"""
import os

import pytest

from app.ingest import default_registry as registry
from app.services import correlation as corr
from app.services.correlation import CorrelationEngine, get_correlation_engine

LOGS = os.path.join(os.path.dirname(__file__), "corpus", "logs")


class FakeRedis:
    """Redis minimale: incr/expire/set(nx)/get, con TTL ignorato (finestra)."""

    def __init__(self):
        self.data = {}
        self.ttl = {}

    async def incr(self, key):
        self.data[key] = int(self.data.get(key, 0)) + 1
        return self.data[key]

    async def expire(self, key, seconds):
        self.ttl[key] = seconds
        return True

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.data:
            return None
        self.data[key] = value
        if ex:
            self.ttl[key] = ex
        return True

    async def get(self, key):
        return self.data.get(key)


class BrokenRedis:
    async def incr(self, *a, **k):
        raise ConnectionError("redis down")

    async def expire(self, *a, **k):
        raise ConnectionError("redis down")

    async def set(self, *a, **k):
        raise ConnectionError("redis down")

    async def get(self, *a, **k):
        raise ConnectionError("redis down")


@pytest.fixture
def fake_redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(corr, "rc", fake)
    return fake


def _lines(filename: str):
    with open(os.path.join(LOGS, filename), encoding="utf-8") as fh:
        return fh.read().splitlines()


def _event(line: str, source: str):
    result = registry.parse(source, line, {"source": "corr-test"})
    assert result.events, result.errors
    return result.events[0]


def _auth_failures(count: int, ip: str = "203.0.113.9"):
    """Genera N fallimenti di autenticazione distinti dallo stesso IP."""
    events = []
    for i in range(count):
        line = (f"<134>1 2026-09-15T12:00:{i:02d}.000000+00:00 web-01 sshd 22{i} ID47 - "
                f"Failed password for invalid user admin from {ip} port {51000 + i} ssh2")
        events.append(_event(line, "syslog"))
    return events


def _auth_success(ip: str = "203.0.113.9"):
    line = (f"<38>1 2026-09-15T12:05:00.000000+00:00 web-01 sshd 2299 ID48 - "
            f"Accepted password for admin from {ip} port 51234 ssh2")
    return _event(line, "syslog")


# ── caricamento e copertura ──────────────────────────────────────────────────
def test_bundled_rules_are_all_executable():
    coverage = get_correlation_engine().coverage()
    assert coverage["rules_total"] >= 5
    assert coverage["rules_executable"] == coverage["rules_total"]
    assert coverage["excluded"] == []
    assert coverage["by_type"]["threshold"] >= 1
    assert coverage["by_type"]["sequence"] >= 1


def test_unsupported_rule_is_excluded_and_explained(tmp_path):
    """Una regola che non sappiamo eseguire deve essere esclusa, non eseguita a metà."""
    (tmp_path / "bad.yml").write_text(
        "title: Unsupported\nid: corr-bad\ntype: frequency\nmatch:\n  event_type: x\n",
        encoding="utf-8")
    (tmp_path / "partial.yml").write_text(
        "title: Partial\nid: corr-partial\ntype: threshold\nmatch:\n  field|unknownmod: value\n",
        encoding="utf-8")
    engine = CorrelationEngine(str(tmp_path))
    assert engine.executable_rules() == []
    reasons = {r["id"]: r["reason"] for r in engine.coverage()["excluded"]}
    assert reasons["corr-bad"]
    assert reasons["corr-partial"]


# ── threshold ────────────────────────────────────────────────────────────────
async def test_threshold_fires_at_n_and_only_once(fake_redis):
    engine = CorrelationEngine()
    events = _auth_failures(5)
    matches = await engine.evaluate(events)
    assert [m.rule_id for m in matches] == ["corr-ssh-bruteforce"]
    match = matches[0]
    assert match.severity == "HIGH"
    assert match.group_label == "203.0.113.9"
    assert match.observed == 5
    # Sesto evento oltre soglia: nessun nuovo alert (fire-once per finestra).
    assert await engine.evaluate([_auth_failures(6)[-1]]) == []


async def test_threshold_below_n_does_not_fire(fake_redis):
    engine = CorrelationEngine()
    assert await engine.evaluate(_auth_failures(4)) == []


async def test_threshold_groups_are_independent(fake_redis):
    engine = CorrelationEngine()
    events = _auth_failures(4, "198.51.100.7") + _auth_failures(4, "203.0.113.9")
    assert await engine.evaluate(events) == []


async def test_threshold_ignores_other_source_types(fake_redis):
    """La regola è dichiarata per `syslog`: un evento Zeek non deve attivarla,
    anche se porta lo stesso `event_type` che la regola cerca."""
    engine = CorrelationEngine()
    with open(os.path.join(LOGS, "zeek_conn.log"), encoding="utf-8") as fh:
        result = registry.parse("zeek", fh.read(), {"source": "corr-test"})
    assert result.events
    zeek_events = []
    for event in result.events[:6]:
        event.extra["event_type"] = "auth_failure"
        event.src_ip = "203.0.113.9"
        zeek_events.append(event)
    assert await engine.evaluate(zeek_events) == []


async def test_rule_matches_only_its_own_source_type(fake_redis):
    """Controprova: gli stessi eventi dichiarati `syslog` fanno scattare la regola."""
    engine = CorrelationEngine()
    events = _auth_failures(5)
    assert [e.source_type for e in events] == ["syslog"] * 5
    assert [m.rule_id for m in await engine.evaluate(events)] == ["corr-ssh-bruteforce"]


async def test_rule_without_group_field_is_skipped(fake_redis):
    """Se il campo di raggruppamento manca, la regola non è applicabile."""
    engine = CorrelationEngine()
    event = _auth_failures(1)[0]
    assert event.src_ip  # sanity: il campo esiste su un evento normale
    event.src_ip = None
    assert await engine.evaluate([event]) == []


# ── sequence ─────────────────────────────────────────────────────────────────
async def test_sequence_fires_on_failures_then_success(fake_redis):
    engine = CorrelationEngine()
    matches = await engine.evaluate(_auth_failures(5) + [_auth_success()])
    ids = [m.rule_id for m in matches]
    assert "corr-bruteforce-success" in ids
    seq = next(m for m in matches if m.rule_id == "corr-bruteforce-success")
    assert seq.severity == "CRITICAL"
    assert seq.observed == 2


async def test_sequence_success_without_failures_does_not_fire(fake_redis):
    engine = CorrelationEngine()
    assert await engine.evaluate([_auth_success()]) == []


async def test_sequence_needs_full_arming_count(fake_redis):
    engine = CorrelationEngine()
    # 4 fallimenti (< count 5) + successo: lo step precedente non è armato.
    assert await engine.evaluate(_auth_failures(4) + [_auth_success()]) == []


async def test_sequence_is_fire_once_per_window(fake_redis):
    engine = CorrelationEngine()
    first = await engine.evaluate(_auth_failures(5) + [_auth_success()])
    assert first
    second = await engine.evaluate([_auth_success()])
    assert second == []


# ── degradazione ─────────────────────────────────────────────────────────────
async def test_redis_failure_does_not_raise_and_does_not_false_positive(monkeypatch):
    """Redis giù: la correlazione salta, l'ingestione no."""
    monkeypatch.setattr(corr, "rc", BrokenRedis())
    engine = CorrelationEngine()
    assert await engine.evaluate(_auth_failures(10)) == []


async def test_evaluate_never_raises_on_broken_rule(fake_redis):
    engine = CorrelationEngine()
    rule = engine.rules()[0]
    # Un matcher che esplode non deve far cadere la valutazione degli altri.
    engine._rules = [rule]
    rule._matchers = [lambda _e: (_ for _ in ()).throw(RuntimeError("boom"))]
    assert await engine.evaluate(_auth_failures(6)) == []


def test_match_dict_is_ui_ready(fake_redis):
    async def run():
        engine = CorrelationEngine()
        matches = await engine.evaluate(_auth_failures(5))
        return matches[0].to_dict()

    import asyncio
    payload = asyncio.run(run())
    assert payload["rule_id"] == "corr-ssh-bruteforce"
    assert payload["engine"] == "correlation"
    assert payload["group"] == "203.0.113.9"
    assert payload["mitre_techniques"]
