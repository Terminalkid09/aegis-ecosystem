"""Audit hardening: test puri (niente DB/rete) per i fix di sicurezza."""
import pytest

from app.core.security import create_access_token, decode_access_token
from app.rules.heuristic_engine import is_regex_safe
from app.services.ai_service import allowed_model
from app.services.alert_enrichment import is_public_ip
from app.services.telemetry_service import _bound_telemetry_data


def test_jwt_carries_iss_aud():
    token, jti, exp = create_access_token("1", "analyst")
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["iss"] == "aegis-brain"
    assert payload["aud"] == "aegis-api"


def test_jwt_without_iss_aud_rejected():
    import jwt as pyjwt
    from app.core.config import settings
    from datetime import datetime, timedelta, timezone
    import uuid
    legacy = pyjwt.encode(
        {"sub": "1", "role": "admin",
         "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
         "jti": str(uuid.uuid4())},
        settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    assert decode_access_token(legacy) is None


@pytest.mark.parametrize("pattern,ok", [
    ("mimikatz", True),
    ("powershell.*-enc", True),
    ("(a|b){2,4}c", True),  # ripetizione limitata: sicura
    ("(a+)+b", False),
    ("(x*)*", False),
    ("(a|b)+c", False),
    ("([", False),
    ("x" * 201, False),
    ("", False),
])
def test_regex_safety_gate(pattern, ok):
    assert (is_regex_safe(pattern) is None) is ok


def test_allowed_model_defaults_and_allowlist(monkeypatch):
    from app.core.config import settings
    assert allowed_model(None) == settings.OLLAMA_DEFAULT_MODEL
    assert allowed_model("tinyllama") == "tinyllama"
    with pytest.raises(ValueError):
        allowed_model("evil-puller:latest")
    monkeypatch.setattr(settings, "OLLAMA_ALLOWED_MODELS", "mistral, gemma2")
    assert allowed_model("mistral") == "mistral"


@pytest.mark.parametrize("ip,public", [
    ("8.8.8.8", True), ("1.1.1.1", True),
    ("10.0.0.1", False), ("192.168.1.1", False),
    ("172.16.0.1", False), ("172.20.5.4", False), ("172.31.255.255", False),
    ("127.0.0.1", False), ("169.254.1.1", False),
    ("100.64.0.1", False), ("0.0.0.0", False),
    ("::1", False), ("fe80::1", False), ("fc00::1", False),
    ("999.999.999.999", False), ("not-an-ip", False),
])
def test_public_ip_gate(ip, public):
    assert is_public_ip(ip) is public


@pytest.mark.asyncio
async def test_login_throttle_blocks_after_10_fails(monkeypatch):
    import app.core.security as sec

    class FakeRedis:
        def __init__(self):
            self.store = {}

        async def get(self, k):
            return self.store.get(k)

        async def incr(self, k):
            self.store[k] = int(self.store.get(k, 0)) + 1
            return self.store[k]

        async def expire(self, k, ttl):
            return True

        async def delete(self, k):
            self.store.pop(k, None)

    monkeypatch.setattr(sec, "redis_client", FakeRedis())
    assert await sec.login_throttled("a@b.co") is False
    for _ in range(10):
        await sec.record_login_failure("a@b.co")
    assert await sec.login_throttled("a@b.co") is True
    await sec.clear_login_failures("a@b.co")
    assert await sec.login_throttled("a@b.co") is False


def test_telemetry_bounds():
    data = _bound_telemetry_data({
        "processes": [{"pid": i} for i in range(600)],
        "capabilities": {"blob": "x" * 20000},
        "cpu_usage": 12.5,
    })
    assert len(data["processes"]) == 500
    assert data["capabilities"] == {"truncated": True, "note": "oversize>8192B"}
    assert data["cpu_usage"] == 12.5


@pytest.mark.asyncio
async def test_rate_guard_redis_first_then_local():
    from app.core.rate_guard import RateGuard

    class FakeRedis:
        def __init__(self):
            self.counts = {}

        async def eval(self, *a, **k):
            key = a[2]
            self.counts[key] = self.counts.get(key, 0) + 1
            return self.counts[key]

        async def incr(self, key):
            self.counts[key] = self.counts.get(key, 0) + 1
            return self.counts[key]

    rg = RateGuard(events_per_min=2)
    rg._client = FakeRedis()
    assert await rg.allow_async("a1") is True
    assert await rg.allow_async("a1") is True
    assert await rg.allow_async("a1") is False  # condiviso, non per-worker
    # Senza Redis: fallback locale identico al vecchio comportamento.
    rg2 = RateGuard(events_per_min=1)
    rg2._client = None
    import app.core.rate_guard as rgmod
    orig = rgmod._redis_client
    rgmod._redis_client = lambda: None
    try:
        assert rg2.allow("a2") is True
        assert rg2.allow("a2") is False
    finally:
        rgmod._redis_client = orig
