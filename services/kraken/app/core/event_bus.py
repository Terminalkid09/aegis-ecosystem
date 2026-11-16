from __future__ import annotations
import asyncio
from collections import defaultdict
from typing import Any, Callable, Coroutine, Dict, List, Set, Tuple
from loguru import logger

AsyncHandler = Callable[..., Coroutine[Any, Any, None]]


class EventBus:
    def __init__(self):
        self._subscribers: dict[str, List[AsyncHandler]] = defaultdict(list)
        self._handler_map: Dict[int, str] = {}

    def subscribe(self, event: str, handler: AsyncHandler, plugin_id: str | None = None) -> None:
        self._subscribers[event].append(handler)
        self._handler_map[id(handler)] = plugin_id or "core"
        logger.debug(f"Handler registered for event '{event}' (plugin: {plugin_id or 'core'})")

    def unsubscribe(self, event: str, handler: AsyncHandler) -> None:
        self._subscribers[event] = [h for h in self._subscribers[event] if h is not handler]
        self._handler_map.pop(id(handler), None)
        logger.debug(f"Handler removed from event '{event}'")

    async def emit(self, event: str, **kwargs: Any) -> List[Any]:
        results: List[Any] = []
        for handler in self._subscribers.get(event, []):
            try:
                result = await handler(**kwargs)
                results.append(result)
            except Exception as e:
                logger.error(f"Handler for event '{event}' failed: {e}")
        return results

    async def emit_async(self, event: str, **kwargs: Any) -> None:
        tasks = []
        for handler in self._subscribers.get(event, []):
            tasks.append(asyncio.create_task(self._safe_call(event, handler, kwargs)))
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_call(self, event: str, handler: AsyncHandler, kwargs: dict) -> None:
        try:
            await handler(**kwargs)
        except Exception as e:
            logger.error(f"Async handler for event '{event}' failed: {e}")

    def get_subscribed_plugins(self, event: str) -> Set[str]:
        plugins: Set[str] = set()
        for handler in self._subscribers.get(event, []):
            pid = self._handler_map.get(id(handler), "core")
            if pid != "core":
                plugins.add(pid)
        return plugins

    def clear_plugin_handlers(self, plugin_id: str) -> None:
        handler_ids_to_remove = {hid for hid, pid in self._handler_map.items() if pid == plugin_id}
        for event in list(self._subscribers.keys()):
            self._subscribers[event] = [
                h for h in self._subscribers[event]
                if id(h) not in handler_ids_to_remove
            ]
        for hid in handler_ids_to_remove:
            self._handler_map.pop(hid, None)
        logger.debug(f"Cleared {len(handler_ids_to_remove)} handlers for plugin '{plugin_id}'")

    @property
    def events(self) -> List[str]:
        return list(self._subscribers.keys())

    @property
    def handler_count(self) -> int:
        return sum(len(v) for v in self._subscribers.values())


event_bus = EventBus()
