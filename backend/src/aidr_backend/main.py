from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI

# Load .env from the repo root (two levels up from src/aidr_backend/).
# Variables already set in the environment take priority — this means Docker
# and CI env vars always win over the file, which is the correct behaviour.
# __file__ = backend/src/aidr_backend/main.py
# .parent   = backend/src/aidr_backend/
# .parent²  = backend/src/
# .parent³  = backend/
# .parent⁴  = repo root  ← .env lives here
load_dotenv(Path(__file__).parents[3] / ".env")

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
