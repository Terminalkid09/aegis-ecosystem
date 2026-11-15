"""AEGIS-LOGIC-005: readiness deve leggere le liste Redis reali."""
import asyncio

from app.core import health as health_mod


class FakeRedis:
    def __init__(self):
        self.depths = {
            "aegis:events": 4,
            "aegis:events:processing": 2,
            "aegis:events:dlq": 1,
        }

    async def llen(self, key):
        return self.depths[key]

    async def aclose(self):
        return None


def test_pipeline_uses_real_queue_keys(monkeypatch):
    monkeypatch.setattr(health_mod.redis, "from_url", lambda *a, **k: FakeRedis())
    result = asyncio.run(health_mod.HealthChecker()._check_pipeline())

    assert result.details["queue_depth"] == 4
    assert result.details["processing"] == 2
    assert result.details["dlq"] == 1
    assert result.details["in_flight"] == 6
