from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, status

from ..middleware.auth import require_api_key
from ..schemas.events import TelemetryEvent

logger = logging.getLogger(__name__)

router = APIRouter(tags=["events"])


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
def ingest_event(
    event: TelemetryEvent,
    _: str = Depends(require_api_key),
) -> dict:
    """
    Receive a single telemetry event from an agent.

    Phase 1: validates the payload and logs receipt. The detection engine
    (Phase 3) will be wired in here — this endpoint is intentionally thin.

    Returns 202 Accepted rather than 200 OK because processing (rule evaluation,
    alerting) will eventually be async.
    """
    # Log at structured INFO level. raw payload is excluded — it may contain
    # sensitive values (usernames, IPs) that should not appear in app logs.
    logger.info(
        "event_received host_id=%s event_type=%s action=%s ts=%s",
        event.host_id,
        event.event_type.value,
        event.action,
        event.ts.isoformat(),
    )

    # TODO (Phase 3): pass event to detection engine
    # TODO (Phase 5): persist event to storage

    return {"accepted": True}
