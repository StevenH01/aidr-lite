from __future__ import annotations

import logging
import os

from fastapi import FastAPI

from .api.routes_alerts import router as alerts_router
from .api.routes_events import router as events_router
from .api.routes_hosts import router as hosts_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="AIDR-Lite Backend",
    version="0.1.0",
    # Disable the interactive docs in production — they expose your schema.
    # Set AIDR_DOCS_ENABLED=true only in dev/lab environments.
    docs_url="/docs" if os.environ.get("AIDR_DOCS_ENABLED", "false").lower() == "true" else None,
    redoc_url=None,
)

app.include_router(events_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(hosts_router, prefix="/api")


@app.get("/health")
def health() -> dict:
    return {"ok": True}
