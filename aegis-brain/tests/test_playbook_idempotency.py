"""Test per il fix Audit L1: i playbook SOAR sono idempotenti per alert.

Prima del fix il cooldown era per-agente e durava 60s: un alert non risolto
ri-attivava il playbook a ogni ciclo di telemetria, rieseguendo contenimento
(kill/isolate/eradicate) su un incidente già gestito. Questi test usano un
Redis finto e un DB finto: nessun PG/Redis richiesto.
"""
import sys
import types
from types import SimpleNamespace

import pytest

from app.services import playbook_engine


class FakeRedis:
    """Redis minimo: get/set(nx)/setex, con contatore di esecuzioni."""

    def __init__(self):
        self.kv = {}
        self.setex_calls = []

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True

    async def setex(self, key, ttl, value):
        self.setex_calls.append((key, ttl))
        self.kv[key] = value
        return True


class _Scalars:
    def __init__(self, items):
        self._items = items

    def all(self):
        return self._items


class _Result:
    def __init__(self, items):
        self._items = items

    def scalars(self):
        return _Scalars(self._items)


class FakeDB:
    """DB finto: risponde alle due select usate dal motore playbook."""

    def __init__(self, playbooks, actions):
        self.playbooks = playbooks
        self.actions = actions
        self.added = []
        self.commits = 0

    async def execute(self, stmt):
        sql = str(stmt)
        if "playbook_actions" in sql:
            return _Result(self.actions)
        return _Result(self.playbooks)

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        return None

    async def commit(self):
        self.commits += 1


def _alert(alert_id=42, severity="HIGH", event_type="PROCESS_CREATED", process_name="mimikatz.exe", pid=1337,
           agent_id="11111111-1111-1111-1111-111111111111"):
    return SimpleNamespace(
        id=alert_id, agent_id=agent_id,
        severity=severity, event_type=event_type, process_name=process_name,
        pid=pid, description="test alert",
    )


def _playbook(pb_id=7):
    return SimpleNamespace(
        id=pb_id, name="isolate-on-high", is_active=True,
        trigger_severity="HIGH", trigger_event_type=None, trigger_process_name=None,
    )


def _action():
    return SimpleNamespace(
        id=1, playbook_id=7, action_type="kill_process", target="", params=None, order=0,
    )


@pytest.fixture()
def patched(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(playbook_engine, "rc", fake)
    executed = []

    async def fake_execute(db, action, alert):
        executed.append((action.action_type, alert.id))
        return {"status": "completed", "output": "ok"}

    monkeypatch.setattr(playbook_engine, "_execute_action", fake_execute)
    return fake, executed


@pytest.mark.asyncio
async def test_playbook_runs_once_per_alert(patched):
    fake, executed = patched
    alert = _alert()
    db = FakeDB([_playbook()], [_action()])

    await playbook_engine.check_and_execute_playbooks(db, alert)
    assert executed == [("kill_process", 42)], "prima esecuzione attesa"

    # Stessa telemetria/alert di nuovo (era il bug: riesecuzione ogni 60s)
    await playbook_engine.check_and_execute_playbooks(db, alert)
    assert executed == [("kill_process", 42)], "l'alert deve essere idempotente"

    await playbook_engine.check_and_execute_playbooks(db, alert)
    assert len(executed) == 1, "mai più di una esecuzione per (playbook, alert)"
    assert "playbook:exec:7:42" in fake.kv


@pytest.mark.asyncio
async def test_playbook_runs_for_different_alerts(patched):
    """Incidenti diversi (host diversi) devono eseguire entrambi."""
    fake, executed = patched
    db = FakeDB([_playbook()], [_action()])

    await playbook_engine.check_and_execute_playbooks(db, _alert(alert_id=1, agent_id="aaaa"))
    await playbook_engine.check_and_execute_playbooks(db, _alert(alert_id=2, agent_id="bbbb"))

    assert executed == [("kill_process", 1), ("kill_process", 2)]
    assert "playbook:exec:7:1" in fake.kv and "playbook:exec:7:2" in fake.kv


@pytest.mark.asyncio
async def test_agent_cooldown_anti_burst(patched):
    """Anti-burst sullo stesso agente: il 2° alert entro 60s non esegue (by design).

    È una scelta esplicita (protezione anti-tempesta), non il vecchio bug:
    con l'idempotency key per alert la riesecuzione infinita è già esclusa.
    """
    fake, executed = patched
    db = FakeDB([_playbook()], [_action()])

    await playbook_engine.check_and_execute_playbooks(db, _alert(alert_id=1))
    await playbook_engine.check_and_execute_playbooks(db, _alert(alert_id=2))

    assert executed == [("kill_process", 1)]
    assert "playbook:cooldown:7:11111111-1111-1111-1111-111111111111" in fake.kv


@pytest.mark.asyncio
async def test_playbook_skips_when_idempotency_store_down(monkeypatch):
    """Fail-closed: senza store dell'idempotenza non si esegue contenimento."""
    class BrokenRedis:
        async def get(self, key):
            raise RuntimeError("redis down")

        async def set(self, *a, **kw):
            raise RuntimeError("redis down")

        async def setex(self, *a, **kw):
            raise RuntimeError("redis down")

    monkeypatch.setattr(playbook_engine, "rc", BrokenRedis())
    executed = []

    async def fake_execute(db, action, alert):
        executed.append(action.action_type)
        return {"status": "completed"}

    monkeypatch.setattr(playbook_engine, "_execute_action", fake_execute)
    db = FakeDB([_playbook()], [_action()])

    await playbook_engine.check_and_execute_playbooks(db, _alert())
    assert executed == [], "store non disponibile => nessuna azione distruttiva"


@pytest.mark.asyncio
async def test_dry_run_has_no_side_effects(patched, monkeypatch):
    fake, executed = patched
    db = FakeDB([_playbook()], [_action()])

    await playbook_engine.check_and_execute_playbooks(db, _alert(), dry_run=True)

    assert executed == [], "dry-run non deve eseguire azioni"
    assert not any(k.startswith("playbook:exec:") for k in fake.kv), "dry-run non consuma l'idempotency key"
