from __future__ import annotations

import os
import secrets

from fastapi import HTTPException, Query, Security, status
from fastapi.security import APIKeyHeader

_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def _expected_key() -> str:
    """Read the configured key at call time so rotation = restart, not redeploy."""
    expected = os.environ.get("BACKEND_API_KEY", "").strip()
    if not expected:
        # Fail closed: misconfigured server should reject all requests.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server authentication is not configured.",
        )
    return expected


def _check(provided: str | None) -> None:
    """Raise 401 unless `provided` matches the expected key (timing-safe)."""
    expected = _expected_key()
    if not provided or not secrets.compare_digest(provided.encode(), expected.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


def require_api_key(api_key: str | None = Security(_API_KEY_HEADER)) -> str:
    """
    Strict header-only auth. Use for all normal endpoints.

    Sends the key as X-API-Key. Never accepts it via query string — query
    params end up in proxy/load-balancer access logs.
    """
    _check(api_key)
    assert api_key is not None  # narrowing for type-checkers
    return api_key


def require_api_key_or_query(
    api_key_header: str | None = Security(_API_KEY_HEADER),
    api_key_query: str | None = Query(default=None, alias="api_key"),
) -> str:
    """
    Permissive auth that accepts the key via header OR ?api_key= query string.

    Exists ONLY for the SSE /events/stream endpoint, because the browser
    EventSource API cannot set custom request headers. Header is preferred
    when both are sent.

    Tradeoff (lab note): query-param keys appear in access logs. Acceptable
    for a local dev dashboard; for production, swap SSE auth to a short-lived
    signed token issued via a separate POST /auth/dashboard-token endpoint.
    """
    provided = api_key_header or api_key_query
    _check(provided)
    assert provided is not None
    return provided
