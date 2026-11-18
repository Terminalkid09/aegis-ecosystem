"""Agent secret verification is cached without weakening revocation checks."""
import asyncio
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from app.core.agent_deps import _AgentSecretCache, _verify_agent_secret
from app.core.security import device_token_proof


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
        # First query: the agent. Second query: revocation lookup.
        return _Result(self.agent if self.calls % 2 == 1 else None)


def _agent(agent_id, stored_hash="stored-hash-v1", meta=None):
    return SimpleNamespace(
        agent_id=agent_id, device_token_hash=stored_hash, meta=meta or {}
    )


def test_verified_secret_is_cached_for_repeated_reports():
    agent_id = uuid.uuid4()
    db = _DB(_agent(agent_id))

    async def twice():
        await _verify_agent_secret(str(agent_id), "Bearer device-secret", db)
        await _verify_agent_secret(str(agent_id), "Bearer device-secret", db)

    with patch("app.core.agent_deps.verify_password", return_value=True) as verify:
        asyncio.run(twice())

    assert verify.call_count == 1


def test_changed_stored_hash_invalidates_cache():
    agent_id = uuid.uuid4()
    first = _DB(_agent(agent_id, "stored-hash-v1"))
    second = _DB(_agent(agent_id, "stored-hash-v2"))

    async def both():
        await _verify_agent_secret(str(agent_id), "Bearer device-secret", first)
        await _verify_agent_secret(str(agent_id), "Bearer device-secret", second)

    with patch("app.core.agent_deps.verify_password", return_value=True) as verify:
        asyncio.run(both())

    assert verify.call_count == 2


def test_invalid_secret_is_not_cached():
    agent_id = uuid.uuid4()

    async def twice():
        # A fresh DB per attempt: the invalid path raises before the revocation
        # lookup, so the same mock cannot model both queries.
        with pytest.raises(HTTPException):
            await _verify_agent_secret(
                str(agent_id), "Bearer wrong", _DB(_agent(agent_id))
            )
        with pytest.raises(HTTPException):
            await _verify_agent_secret(
                str(agent_id), "Bearer wrong", _DB(_agent(agent_id))
            )

    with patch("app.core.agent_deps.verify_password", return_value=False) as verify:
        asyncio.run(twice())

    assert verify.call_count == 2


def test_fast_proof_skips_argon2():
    agent_id = uuid.uuid4()
    stored = "stored-hash-v1"
    agent = _agent(
        agent_id, stored,
        meta={"device_token_proof": device_token_proof("device-secret", stored)},
    )

    with patch("app.core.agent_deps.verify_password", return_value=False) as verify:
        asyncio.run(_verify_agent_secret(
            str(agent_id), "Bearer device-secret", _DB(agent)
        ))

    assert verify.call_count == 0


def test_stale_proof_does_not_authorize_old_token():
    agent_id = uuid.uuid4()
    agent = _agent(
        agent_id, "stored-hash-v2",
        meta={"device_token_proof": device_token_proof("device-secret", "stored-hash-v1")},
    )

    with patch("app.core.agent_deps.verify_password", return_value=False) as verify:
        with pytest.raises(HTTPException) as exc:
            asyncio.run(_verify_agent_secret(
                str(agent_id), "Bearer device-secret", _DB(agent)
            ))

    assert exc.value.status_code == 401
    assert verify.call_count == 1


def test_successful_argon2_backfills_the_fast_proof():
    agent_id = uuid.uuid4()
    agent = _agent(agent_id, "stored-hash-v1")

    with patch("app.core.agent_deps.verify_password", return_value=True) as verify:
        asyncio.run(_verify_agent_secret(
            str(agent_id), "Bearer device-secret", _DB(agent)
        ))

    assert verify.call_count == 1
    assert agent.meta["device_token_proof"] == device_token_proof(
        "device-secret", "stored-hash-v1"
    )


def test_cache_expires_and_is_bounded():
    cache = _AgentSecretCache(ttl=0.01, max_entries=2)
    cache.remember("a", "token", "hash")
    assert cache.valid("a", "token", "hash")
    for index in range(5):
        cache.remember(f"a{index}", "token", "hash")
    assert len(cache._entries) <= 2
    cache.clear()
    assert not cache.valid("a", "token", "hash")
