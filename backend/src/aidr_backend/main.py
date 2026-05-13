from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

# Load .env from the repo root.
# __file__ = backend/src/aidr_backend/main.py
# .parents[3] = repo root  (aidr-lite/)
load_dotenv(Path(__file__).parents[3] / ".env")

from .api.routes_alerts import router as alerts_router  # noqa: E402
from .api.routes_events import router as events_router  # noqa: E402
from .api.routes_hosts import router as hosts_router  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="AIDR-Lite Backend",
    version="0.1.0",
    docs_url="/docs" if os.environ.get("AIDR_DOCS_ENABLED", "false").lower() == "true" else None,
    redoc_url=None,
)

app.include_router(events_router, prefix="/api")
app.include_router(alerts_router, prefix="/api")
app.include_router(hosts_router, prefix="/api")


# Mount the dashboard at /dashboard — repo_root/dashboard/ contains index.html.
# Same-origin: dashboard fetches the API at relative paths, no CORS needed.
_DASHBOARD_DIR = Path(__file__).parents[3] / "dashboard"
if _DASHBOARD_DIR.is_dir():
    app.mount(
        "/dashboard",
        StaticFiles(directory=_DASHBOARD_DIR, html=True),
        name="dashboard",
    )


@app.get("/health")
def health() -> dict:
    return {"ok": True}


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    """Friendly redirect so visiting / lands on the dashboard."""
    return RedirectResponse(url="/dashboard/")
