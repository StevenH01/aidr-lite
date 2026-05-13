"""
In-memory event buffer with async pub/sub for SSE subscribers.

This is the Phase 2 stand-in for real persistence. It does two jobs:

1. Holds the last N events in a bounded ring so newly-connected dashboard
   clients can render recent history immediately on page load.
2. Fans out new events to any number of asyncio.Queue subscribers, which
   Server-Sent Events handlers drain into long-lived HTTP responses.

Lab note: events are lost on process restart. Phase 5 swaps this for SQLite
without changing the public API surface (add/recent/subscribe/unsubscribe).
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Any

logger = logging.getLogger(__name__)


class EventBuffer:
    def __init__(self, capacity: int = 1000, subscriber_queue_size: int = 200) -> None:
        # Bounded deque: oldest events evicted automatically when capacity is hit.
        self._events: deque[dict[str, Any]] = deque(maxlen=capacity)
        # Each SSE client owns one queue. Bounded so a single slow consumer
        # cannot exhaust memory by stalling the producer.
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._subscriber_queue_size = subscriber_queue_size

    def add(self, event: dict[str, Any]) -> None:
        """Append an event and broadcast it to all subscribers."""
        self._events.append(event)

        # Snapshot to a list so we can mutate _subscribers safely if a
        # disconnected client raises during put_nowait cleanup.
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Slow consumer — drop the event for that client only.
                # Logged at WARNING so we notice if it happens repeatedly.
                logger.warning("dropped event for slow SSE subscriber")

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return up to `limit` most recent events, oldest first."""
        if limit <= 0:
            return []
        # deque slicing isn't supported; convert to list for the tail.
        return list(self._events)[-limit:]

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """Register a new SSE subscriber and return its queue."""
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._subscriber_queue_size)
        self._subscribers.add(q)
        logger.info("sse subscriber connected (total=%d)", len(self._subscribers))
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        """Drop a subscriber. Safe to call multiple times."""
        self._subscribers.discard(q)
        logger.info("sse subscriber disconnected (total=%d)", len(self._subscribers))


# Module-level singleton — one buffer per backend process.
_buffer: EventBuffer | None = None


def get_buffer() -> EventBuffer:
    global _buffer
    if _buffer is None:
        _buffer = EventBuffer()
    return _buffer
