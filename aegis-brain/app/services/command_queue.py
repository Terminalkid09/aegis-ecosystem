"""Agente command queue: bounded, atomic enqueue and at-least-once delivery.

The queue stores an envelope (`id`, `command`, `attempts`). A poll atomically
moves the envelope to a per-agent processing list and returns a flattened
command with `delivery_id`. The agent acknowledges that id after execution.
If it crashes before the ack, the processing entry is requeued after the
visibility timeout; after `COMMAND_MAX_DELIVERIES` it goes to a DLQ instead of
looping forever. This is at-least-once, not exactly-once: duplicate execution is
possible and callers must keep actions idempotent where possible.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, List

from app.core.config import settings

_ENQUEUE_LUA = """
local limit = tonumber(ARGV[1])
local depth = redis.call('LLEN', KEYS[1])
if depth >= limit then
  return {0, depth}
end
redis.call('RPUSH', KEYS[1], ARGV[2])
return {1, depth + 1}
"""

_REAP_LUA = """
local now = tonumber(ARGV[1])
local visibility = tonumber(ARGV[2])
local max_deliveries = tonumber(ARGV[3])
local items = redis.call('LRANGE', KEYS[1], 0, -1)
for _, raw in ipairs(items) do
  local item = cjson.decode(raw)
  local claimed = tonumber(item.claimed_at or 0)
  if now - claimed > visibility then
    redis.call('LREM', KEYS[1], 1, raw)
    if (tonumber(item.attempts) or 0) >= max_deliveries then
      redis.call('RPUSH', KEYS[3], raw)
    else
      redis.call('RPUSH', KEYS[2], raw)
    end
  end
end
return #items
"""

_POP_LUA = """
local limit = tonumber(ARGV[2])
local max_deliveries = tonumber(ARGV[3])
local now = tonumber(ARGV[1])
local out = {}
for i = 1, limit do
  local raw = redis.call('LPOP', KEYS[1])
  if not raw then break end
  local item = cjson.decode(raw)
  item.attempts = (tonumber(item.attempts) or 0) + 1
  if item.attempts > max_deliveries then
    redis.call('RPUSH', KEYS[3], raw)
  else
    item.claimed_at = now
    local encoded = cjson.encode(item)
    redis.call('RPUSH', KEYS[2], encoded)
    table.insert(out, encoded)
  end
end
return out
"""

_ACK_LUA = """
local delivery_id = ARGV[1]
local command_name = ARGV[2]
for _, raw in ipairs(redis.call('LRANGE', KEYS[1], 0, -1)) do
  local item = cjson.decode(raw)
  local matches = false
  if delivery_id ~= '' then
    matches = item.id == delivery_id
  elseif command_name ~= '' and item.command and item.command.command then
    matches = item.command.command == command_name
  end
  if matches then
    redis.call('LREM', KEYS[1], 1, raw)
    return 1
  end
end
return 0
"""


class CommandQueueFull(RuntimeError):
    """The agent queue is at its cap: no command was silently discarded."""

    def __init__(self, agent_id: Any, command: Dict[str, Any], depth: int, limit: int):
        self.agent_id = str(agent_id)
        self.command_name = str(command.get("command") or "unknown")
        self.depth = int(depth)
        self.limit = int(limit)
        super().__init__(
            f"command queue full for agent {self.agent_id} "
            f"({self.depth}/{self.limit}): {self.command_name}"
        )


def command_queue_name(agent_id: Any) -> str:
    return f"aegis:commands:{agent_id}"


def processing_queue_name(agent_id: Any) -> str:
    return f"aegis:commands:{agent_id}:processing"


def dead_letter_queue_name(agent_id: Any) -> str:
    return f"aegis:commands:{agent_id}:dlq"


def _envelope(command: Dict[str, Any]) -> str:
    return json.dumps({
        "id": uuid.uuid4().hex,
        "command": command,
        "attempts": 0,
        "created_at": int(time.time()),
    }, separators=(",", ":"))


def _flatten(raw: str) -> Dict[str, Any] | None:
    try:
        item = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(item, dict):
        return None
    command = item.get("command")
    if isinstance(command, dict):
        out = dict(command)
        out["delivery_id"] = item.get("id")
        out["delivery_attempt"] = int(item.get("attempts") or 0)
        return out
    # A legacy payload written before the envelope format.
    if isinstance(item, dict):
        return item
    return None


async def enqueue_command(
    client,
    agent_id: Any,
    command: Dict[str, Any],
    *,
    max_length: int | None = None,
) -> Dict[str, Any]:
    limit = max(1, int(max_length or settings.COMMAND_QUEUE_MAX))
    queue = command_queue_name(agent_id)
    result = await client.eval(_ENQUEUE_LUA, 1, queue, limit, _envelope(command))
    queued, depth = int(result[0]), int(result[1])
    if not queued:
        try:
            from app.core.metrics import inc
            inc("aegis_commands_dropped_total", 1, 'reason="queue_full"')
        except Exception:
            pass
        return {"queued": False, "reason": "queue_full", "depth": depth, "limit": limit}
    return {"queued": True, "depth": depth, "limit": limit}


async def reap_expired_commands(
    client,
    agent_id: Any,
    *,
    visibility: int | None = None,
    max_deliveries: int | None = None,
) -> int:
    """Move processing entries older than the lease back to the queue/DLQ."""
    visibility = max(1, int(visibility or settings.COMMAND_VISIBILITY_TIMEOUT_S))
    max_deliveries = max(1, int(max_deliveries or settings.COMMAND_MAX_DELIVERIES))
    try:
        result = await client.eval(
            _REAP_LUA, 3,
            processing_queue_name(agent_id),
            command_queue_name(agent_id),
            dead_letter_queue_name(agent_id),
            int(time.time()), visibility, max_deliveries,
        )
        return int(result or 0)
    except Exception:
        return 0


async def pop_commands(
    client,
    agent_id: Any,
    limit: int = 50,
    *,
    visibility: int | None = None,
    max_deliveries: int | None = None,
) -> List[Dict[str, Any]]:
    """Atomically claim up to `limit` commands for an agent."""
    await reap_expired_commands(
        client, agent_id, visibility=visibility, max_deliveries=max_deliveries
    )
    visibility = max(1, int(visibility or settings.COMMAND_VISIBILITY_TIMEOUT_S))
    max_deliveries = max(1, int(max_deliveries or settings.COMMAND_MAX_DELIVERIES))
    raw = await client.eval(
        _POP_LUA, 3,
        command_queue_name(agent_id),
        processing_queue_name(agent_id),
        dead_letter_queue_name(agent_id),
        int(time.time()), max(1, int(limit)), max_deliveries,
    )
    out: List[Dict[str, Any]] = []
    for item in raw or []:
        command = _flatten(item)
        if command:
            out.append(command)
    return out


async def ack_command(
    client,
    agent_id: Any,
    *,
    delivery_id: str | None = None,
    command_name: str | None = None,
) -> bool:
    """Remove a delivered command from processing. Idempotent on retries."""
    if not delivery_id and not command_name:
        return False
    try:
        result = await client.eval(
            _ACK_LUA, 1, processing_queue_name(agent_id),
            delivery_id or "", command_name or "",
        )
        return int(result or 0) > 0
    except Exception:
        return False
