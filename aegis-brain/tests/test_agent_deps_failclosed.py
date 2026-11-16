"""AEGIS-LOGIC-004: errore DB sulla revoca non deve autorizzare l'agente."""
import asyncio
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.core.agent_deps import _verify_agent_secret
from app.core.security import hash_password


class _Result:
    def __init__(self, item=None):
        self._item = item

    def scalars(self):
        return self

    def first(self):
        return self._item


class _DB:
    def __init__(self, agent):
        self.agent = agent
        self.calls = 0

    async def execute(self, stmt):
        self.calls += 1
        if self.calls == 1:
            return _Result(self.agent)
        raise RuntimeError("database unavailable while reading revoked_certs")


def test_revocation_check_error_is_503_not_allow():
    agent_id = uuid.uuid4()
    agent = SimpleNamespace(
        agent_id=agent_id,
        device_token_hash=hash_password("device-secret"),
    )
    with pytest.raises(HTTPException) as exc:
        asyncio.run(_verify_agent_secret(str(agent_id), "Bearer device-secret", _DB(agent)))
    assert exc.value.status_code == 503
    assert "Revocation" in exc.value.detail
