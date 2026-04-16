from __future__ import annotations

from fastapi import APIRouter, Depends

from ..middleware.auth import require_api_key

router = APIRouter(tags=["hosts"])


@router.get("/hosts")
def list_hosts(_: str = Depends(require_api_key)) -> dict:
    """
    Return known hosts that have sent telemetry.

    Phase 1 stub — host registration lands in Phase 5.
    """
    return {"hosts": []}
