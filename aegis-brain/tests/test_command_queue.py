"""AEGIS-LOGIC-003: coda comandi bounded, FIFO e senza perdite silenziose."""
import pytest

from app.services.command_queue import enqueue_command


class FakeRedis:
    def __init__(self):
        self.lists = {}

    async def llen(self, key):
        return len(self.lists.get(key, []))

    async def rpush(self, key, value):
        self.lists.setdefault(key, []).append(value)
        return len(self.lists[key])

    async def ltrim(self, key, start, stop):
        values = self.lists.get(key, [])
        self.lists[key] = values[start:] if stop == -1 else values[start:stop + 1]

    def values(self, agent_id):
        return self.lists.get(f"aegis:commands:{agent_id}", [])


@pytest.mark.asyncio
async def test_full_queue_rejects_the_new_command_instead_of_dropping_it():
    redis = FakeRedis()
    agent = "agent-1"
    for i in range(3):
        result = await enqueue_command(redis, agent, {"command": f"CMD-{i}"}, max_length=3)
        assert result["queued"] is True

    result = await enqueue_command(redis, agent, {"command": "CMD-3"}, max_length=3)

    assert result["queued"] is False
    assert result["reason"] == "queue_full"
    assert len(redis.values(agent)) == 3
    assert "CMD-3" not in "".join(redis.values(agent))


@pytest.mark.asyncio
async def test_trim_keeps_newest_entries_if_two_producers_race(monkeypatch):
    redis = FakeRedis()
    agent = "agent-2"
    await redis.rpush(f"aegis:commands:{agent}", "old-1")
    await redis.rpush(f"aegis:commands:{agent}", "old-2")
    await redis.rpush(f"aegis:commands:{agent}", "old-3")

    # Simula il race: LLEN vede 0 ma la lista contiene gia' tre elementi.
    async def stale_llen(key):
        return 0

    monkeypatch.setattr(redis, "llen", stale_llen)
    await enqueue_command(redis, agent, {"command": "new"}, max_length=3)

    values = redis.values(agent)
    assert len(values) == 3
    assert values[-1].endswith('"new"}')
    assert "old-1" not in "".join(values)
