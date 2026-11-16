"""AEGIS-SEC-006: chiavi per sorgente, hash e revoca."""
import asyncio
from types import SimpleNamespace

from app.core.config import settings
from app.services.api_keys import (
    generate_api_key, hash_api_key, resolve_api_key, source_allowed,
)


class _Result:
    def __init__(self, key):
        self._key = key

    def scalars(self):
        return self

    def first(self):
        return self._key


class FakeDB:
    def __init__(self, key=None):
        self.key = key
        self.calls = 0

    async def execute(self, stmt):
        self.calls += 1
        return _Result(self.key)


def test_generated_key_is_prefixed_and_hashed_only():
    raw = generate_api_key()
    assert raw.startswith("aegis_")
    assert len(raw) > 40
    assert hash_api_key(raw) == hash_api_key(raw)
    assert raw not in hash_api_key(raw)


def test_global_key_still_works_without_db(monkeypatch):
    monkeypatch.setattr(settings, "AEGIS_API_KEY", "global-test-key")
    db = FakeDB()
    auth = asyncio.run(resolve_api_key(db, "global-test-key"))
    assert auth["global"] is True
    assert auth["source"] is None
    assert db.calls == 0


def test_db_key_resolves_source_and_records_last_used():
    key = SimpleNamespace(
        id=7, name="firewall-a", source="src-a",
        scopes={"scopes": ["ingest"]}, active=True,
        revoked_at=None, last_used=None,
    )
    auth = asyncio.run(resolve_api_key(FakeDB(key), "aegis_scoped_key"))
    assert auth["id"] == 7
    assert auth["source"] == "src-a"
    assert auth["scopes"] == {"scopes": ["ingest"]}
    assert key.last_used is not None


def test_source_scope_is_enforced_for_db_keys():
    assert source_allowed({"source": "src-a"}, "src-a") is True
    assert source_allowed({"source": "src-a"}, "src-b") is False
    assert source_allowed({"source": None}, "anything") is True


def test_unknown_or_revoked_key_is_rejected():
    assert asyncio.run(resolve_api_key(FakeDB(None), "aegis_unknown")) is None
    assert asyncio.run(resolve_api_key(FakeDB(None), "")) is None
