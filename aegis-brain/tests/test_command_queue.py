"""Coda comandi bounded e consegna at-least-once (ack + visibility timeout)."""
import asyncio
import json
import os
import subprocess
import sys
import textwrap

import pytest
import redis.asyncio as redis

from app.services import command_queue, telemetry_service
from app.services.command_queue import (
    CommandQueueFull,
    ack_command,
    enqueue_command,
    pop_commands,
)


class FakeRedis:
    """Minimal Redis fake: only the atomic EVAL enqueue path is allowed."""

    def __init__(self):
        self.lists = {}
        self.eval_calls = 0

    async def eval(self, script, numkeys, key, *args):
        assert numkeys == 1
        assert "RPUSH" in script
        self.eval_calls += 1
        limit, value = int(args[0]), args[1]
        values = self.lists.setdefault(key, [])
        if len(values) >= limit:
            return [0, len(values)]
        values.append(value)
        return [1, len(values)]

    def values(self, agent_id):
        return self.lists.get(f"aegis:commands:{agent_id}", [])


@pytest.fixture
async def real_redis():
    client = redis.from_url(
        os.getenv("AEGIS_TEST_REDIS_URL", "redis://127.0.0.1:6379/15"),
        decode_responses=True,
    )
    try:
        await client.ping()
    except Exception:
        await client.aclose()
        pytest.skip("real Redis is required for delivery tests")
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()


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
    assert result["depth"] == 3
    assert len(redis.values(agent)) == 3
    assert "CMD-3" not in "".join(redis.values(agent))


@pytest.mark.asyncio
async def test_enqueue_is_one_atomic_redis_call():
    redis = FakeRedis()
    agent = "agent-atomic"

    result = await enqueue_command(redis, agent, {"command": "ISOLATE_HOST"}, max_length=3)

    assert result == {"queued": True, "depth": 1, "limit": 3}
    assert redis.eval_calls == 1
    assert len(redis.values(agent)) == 1


@pytest.mark.asyncio
async def test_two_producers_cannot_exceed_the_cap(real_redis):
    """La cap e' dentro lo stesso EVAL: due producer non possono superarla."""
    agent = "agent-concurrent"
    results = await asyncio.gather(*(
        enqueue_command(real_redis, agent, {"command": f"CMD-{i}"}, max_length=5)
        for i in range(20)
    ))

    assert sum(1 for result in results if result["queued"]) == 5
    assert sum(
        1 for result in results
        if not result["queued"] and result.get("reason") == "queue_full"
    ) == 15
    assert await real_redis.llen(f"aegis:commands:{agent}") == 5


@pytest.mark.asyncio
async def test_unacked_command_is_redelivered_and_ack_is_idempotent(real_redis):
    agent = "agent-redelivery"
    await enqueue_command(real_redis, agent, {"command": "ISOLATE_HOST"}, max_length=10)

    first = await pop_commands(real_redis, agent, 1, visibility=1, max_deliveries=5)
    assert len(first) == 1
    assert first[0]["command"] == "ISOLATE_HOST"
    assert first[0]["delivery_id"]
    assert await real_redis.llen(f"aegis:commands:{agent}") == 0

    assert await pop_commands(real_redis, agent, 1, visibility=1, max_deliveries=5) == []

    await asyncio.sleep(2.1)
    second = await pop_commands(real_redis, agent, 1, visibility=1, max_deliveries=5)
    assert len(second) == 1
    assert second[0]["delivery_id"] == first[0]["delivery_id"]
    assert second[0]["delivery_attempt"] == 2

    assert await ack_command(real_redis, agent, delivery_id=second[0]["delivery_id"]) is True
    assert await ack_command(real_redis, agent, delivery_id=second[0]["delivery_id"]) is False
    assert await real_redis.llen(f"aegis:commands:{agent}:processing") == 0


@pytest.mark.asyncio
async def test_consumer_restart_after_execution_redelivers_the_same_command(real_redis):
    """A new process must recover the command, not silently acknowledge it.

    The first consumer is closed after the action has run but before the ack,
    which is the dangerous window for a containment command. The second
    connection represents the restarted worker. It must receive the same
    delivery id with attempt=2, so the UI/agent can show a possible duplicate.
    """
    url = os.getenv("AEGIS_TEST_REDIS_URL", "redis://127.0.0.1:6379/15")
    agent = "agent-restart"
    await enqueue_command(real_redis, agent, {"command": "ISOLATE_HOST"}, max_length=10)

    consumer = redis.from_url(url, decode_responses=True)
    first = await pop_commands(consumer, agent, 1, visibility=1, max_deliveries=5)
    assert len(first) == 1
    assert first[0]["command"] == "ISOLATE_HOST"
    await consumer.aclose()  # crash after execution, before ack

    await asyncio.sleep(2.1)
    restarted = redis.from_url(url, decode_responses=True)
    second = await pop_commands(restarted, agent, 1, visibility=1, max_deliveries=5)

    assert len(second) == 1
    assert second[0]["command"] == "ISOLATE_HOST"
    assert second[0]["delivery_id"] == first[0]["delivery_id"]
    assert second[0]["delivery_attempt"] == 2
    assert await ack_command(restarted, agent, delivery_id=second[0]["delivery_id"]) is True
    assert await ack_command(restarted, agent, delivery_id=second[0]["delivery_id"]) is False
    assert await restarted.llen(f"aegis:commands:{agent}:processing") == 0
    await restarted.aclose()


@pytest.mark.asyncio
async def test_worker_process_exit_before_ack_is_recovered_by_new_process(real_redis):
    """Kill a separate worker process after execution, then recover in another."""
    url = os.getenv("AEGIS_TEST_REDIS_URL", "redis://127.0.0.1:6379/15")
    agent = "agent-process-restart"
    await enqueue_command(real_redis, agent, {"command": "KILL_PROCESS"}, max_length=10)

    child = textwrap.dedent("""
        import asyncio, json, os
        import redis.asyncio as redis
        from app.services.command_queue import ack_command, pop_commands

        async def main():
            client = redis.from_url(os.environ["TEST_REDIS_URL"], decode_responses=True)
            try:
                commands = await pop_commands(
                    client, os.environ["TEST_AGENT"], 1,
                    visibility=1, max_deliveries=5,
                )
                if os.environ.get("ACK") == "1":
                    for command in commands:
                        await ack_command(
                            client, os.environ["TEST_AGENT"],
                            delivery_id=command["delivery_id"],
                        )
                print(json.dumps(commands))
            finally:
                await client.aclose()

        asyncio.run(main())
    """)
    env = os.environ.copy()
    env["TEST_REDIS_URL"] = url
    env["TEST_AGENT"] = agent
    env["PYTHONPATH"] = os.getcwd() + os.pathsep + env.get("PYTHONPATH", "")

    first = subprocess.run(
        [sys.executable, "-c", child], cwd=os.getcwd(), env=env,
        capture_output=True, text=True, timeout=20,
    )
    assert first.returncode == 0, first.stderr[-2000:]
    first_command = json.loads(first.stdout.strip().splitlines()[-1])[0]

    await asyncio.sleep(2.1)
    env["ACK"] = "1"
    second = subprocess.run(
        [sys.executable, "-c", child], cwd=os.getcwd(), env=env,
        capture_output=True, text=True, timeout=20,
    )
    assert second.returncode == 0, second.stderr[-2000:]
    second_command = json.loads(second.stdout.strip().splitlines()[-1])[0]

    assert second_command["delivery_id"] == first_command["delivery_id"]
    assert second_command["delivery_attempt"] == 2
    assert await real_redis.llen(f"aegis:commands:{agent}:processing") == 0


@pytest.mark.asyncio
async def test_poison_command_goes_to_dlq_instead_of_looping(real_redis):
    agent = "agent-dlq"
    await enqueue_command(real_redis, agent, {"command": "LOOP"}, max_length=10)
    assert len(await pop_commands(real_redis, agent, 1, visibility=1, max_deliveries=1)) == 1

    await asyncio.sleep(2.1)
    assert await pop_commands(real_redis, agent, 1, visibility=1, max_deliveries=1) == []
    assert await real_redis.llen(f"aegis:commands:{agent}:dlq") == 1
    assert await real_redis.llen(f"aegis:commands:{agent}") == 0


@pytest.mark.asyncio
async def test_send_command_raises_on_full_queue(monkeypatch):
    async def full_queue(*args, **kwargs):
        return {"queued": False, "reason": "queue_full", "depth": 100, "limit": 100}

    monkeypatch.setattr(command_queue, "enqueue_command", full_queue)

    with pytest.raises(CommandQueueFull) as excinfo:
        await telemetry_service.send_command_to_agent("agent-full", {"command": "KILL_PROCESS"})

    assert excinfo.value.command_name == "KILL_PROCESS"
    assert excinfo.value.depth == 100
