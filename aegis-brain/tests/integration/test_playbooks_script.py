"""Audit F-02: azioni playbook 'script' disabilitate di default."""
import types

import pytest
from httpx import AsyncClient

from app.services import playbook_engine


def _action(**kw):
    base = {"action_type": "script", "target": "whoami", "params": {}}
    base.update(kw)
    return types.SimpleNamespace(**base)


@pytest.mark.asyncio
async def test_script_blocked_at_execution_by_default():
    res = await playbook_engine._execute_action(None, _action(), None)
    assert res["status"] == "blocked"


@pytest.mark.asyncio
async def test_script_executes_when_enabled(monkeypatch):
    import sys
    from app.core.config import settings
    monkeypatch.setattr(settings, "PLAYBOOK_SCRIPT_ENABLED", True)
    # sys.executable senza argomenti: esce 0 su ogni OS (echo e' builtin).
    res = await playbook_engine._execute_action(None, _action(target=sys.executable), None)
    assert res["status"] == "completed"


@pytest.mark.asyncio
async def test_create_script_playbook_forbidden_by_default(
        client: AsyncClient, admin_auth_headers):
    r = await client.post("/api/v1/soar/playbooks", json={
        "name": "evil", "actions": [{"action_type": "script", "target": "id"}],
    }, headers=admin_auth_headers)
    assert r.status_code == 403


@pytest.mark.asyncio
async def test_create_script_playbook_allowed_when_enabled(
        client: AsyncClient, admin_auth_headers, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "PLAYBOOK_SCRIPT_ENABLED", True)
    r = await client.post("/api/v1/soar/playbooks", json={
        "name": "audit-test-script", "actions": [{"action_type": "script", "target": "echo hi"}],
    }, headers=admin_auth_headers)
    assert r.status_code in (200, 201)
