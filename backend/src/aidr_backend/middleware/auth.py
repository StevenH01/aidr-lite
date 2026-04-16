from __future__ import annotations

import os
import secrets

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str | None = Security(_API_KEY_HEADER)) -> str:
    """
    FastAPI dependency that validates the X-API-Key request header.

    The expected key is read from the BACKEND_API_KEY environment variable at
    call time (not cached at import time) so the process can be restarted to
    rotate the key without a code redeploy.

    Uses secrets.compare_digest to prevent timing-based key enumeration.

    Lab note: for production, replace with short-lived JWTs or mTLS. A static
    shared secret is sufficient for a trusted internal network MVP.
    """
    expected = os.environ.get("BACKEND_API_KEY", "").strip()

    if not expected:
        # Fail closed: if the key is not configured the service should not
        # accept any requests rather than accidentally allowing all of them.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server authentication is not configured.",
        )

    if not api_key or not secrets.compare_digest(api_key.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return api_key
