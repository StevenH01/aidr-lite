from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import StreamingResponse

from ..middleware.auth import require_api_key, require_api_key_or_query
from ..schemas.events import TelemetryEvent
from ..storage.event_buffer import get_buffer

logger = logging.getLogger(__name__)

router = APIRouter(tags=["events"])


def _serialize(event: TelemetryEvent) -> dict:
    """Convert a validated event to a JSON-safe dict for buffer storage."""
    return event.model_dump(mode="json")


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_event(
    event: TelemetryEvent,
    _: str = Depends(require_api_key),
) -> dict:
    """
    Receive a single telemetry event from an agent.

    Validates the payload, pushes it into the in-memory buffer (which
    fans out to live SSE subscribers), and returns 202.

    TODO (Phase 3): pass to detection engine
    TODO (Phase 5): persist to SQLite
    """
    payload = _serialize(event)
    get_buffer().add(payload)

    logger.info(
        "event_received host_id=%s event_type=%s action=%s",
        event.host_id,
        event.event_type.value,
        event.action,
    )
    return {"accepted": True}


@router.get("/events/recent")
def recent_events(
    limit: int = Query(default=100, ge=1, le=1000),
    _: str = Depends(require_api_key),
) -> dict:
    """
    Return the most recent events from the in-memory buffer.

    Used by the dashboard on first page load to render history before
    the SSE stream takes over for live updates.
    """
    events = get_buffer().recent(limit=limit)
    return {"events": events, "count": len(events)}


@router.get("/events/stream")
async def stream_events(
    request: Request,
    _: str = Depends(require_api_key_or_query),
) -> StreamingResponse:
    """
    Server-Sent Events stream of new telemetry events.

    The browser EventSource API auto-reconnects on disconnect, so the agent
    side doesn't need any retry logic. We send a comment-only keepalive every
    15 seconds to defeat idle-timeout proxies.
    """
    buffer = get_buffer()
    queue = buffer.subscribe()

    async def event_generator():
        try:
            # Initial backfill so newly-connected clients see recent history
            # without making a separate /recent call. Capped to keep the
            # initial flush small.
            for past in buffer.recent(limit=50):
                yield f"data: {json.dumps(past)}\n\n"

            while True:
                # If the client closed the connection, stop pushing.
                if await request.is_disconnected():
                    break

                try:
                    # Wake every 15s to send a keepalive comment if no events
                    # have arrived. SSE comments start with ':' and are
                    # ignored by the EventSource client.
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            buffer.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable nginx buffering if behind one
        },
    )
