"""AEGIS-SEC-003 / D7: l'azione `script` non esiste piu' in 4.1."""
import inspect
import types

import pytest
from httpx import AsyncClient

from app.services import playbook_engine


def _action(**kw):
    base = {"action_type": "script", "target": "whoami", "params": {}}
    base.update(kw)
    return types.SimpleNamespace(**base)


@pytest.mark.asyncio
async def test_script_action_is_blocked_at_execution():
    res = await playbook_engine._execute_action(None, _action(), None)
    assert res["status"] == "blocked"
    assert "removed" in res["output"]


@pytest.mark.asyncio
async def test_create_script_playbook_is_rejected(
        client: AsyncClient, admin_auth_headers):
    r = await client.post("/api/v1/soar/playbooks", json={
        "name": "evil", "actions": [{"action_type": "script", "target": "id"}],
    }, headers=admin_auth_headers)
    assert r.status_code == 400, r.text
    assert "removed" in r.json()["detail"]


def test_no_subprocess_path_in_playbook_engine():
    source = inspect.getsource(playbook_engine)
    assert "import subprocess" not in source
    assert "subprocess.run" not in source
    assert '"script"' not in source or "removed in 4.1" in source
