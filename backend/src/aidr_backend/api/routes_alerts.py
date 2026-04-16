from __future__ import annotations

from fastapi import APIRouter, Depends

from ..middleware.auth import require_api_key

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def list_alerts(_: str = Depends(require_api_key)) -> dict:
    """
    Return generated alerts.

    Phase 1 stub — storage and filtering land in Phase 5.
    """
    return {"alerts": [], "total": 0}
