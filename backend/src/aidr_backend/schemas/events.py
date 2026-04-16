from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class EventType(str, Enum):
    AUTH = "auth"
    PROCESS = "process"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    PERSISTENCE = "persistence"


# Safe identifier pattern: alphanumeric, hyphens, underscores, dots
_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9_\-.]+$")
# Action names: alphanumeric and underscores only (no dots/hyphens — keeps rule matching simple)
_SAFE_ACTION_RE = re.compile(r"^[a-zA-Z0-9_]+$")


class TelemetryEvent(BaseModel):
    """
    Single telemetry event sent from an agent to the backend ingest endpoint.

    All string fields are validated against safe character sets before storage
    or rule evaluation. The `raw` dict carries collector-specific detail and is
    intentionally untyped at this layer — Phase 3 will add per-type sub-schemas
    once the detection engine is wired in.

    Lab note: `raw` may contain log lines with usernames/IPs. Do not log raw
    values at INFO level in production; use DEBUG or omit entirely.
    """

    ts: datetime = Field(..., description="Event timestamp (UTC preferred)")
    host_id: str = Field(..., min_length=1, max_length=128, description="Unique agent host identifier")
    event_type: EventType
    action: str = Field(..., min_length=1, max_length=64, description="Specific action within event_type")
    raw: dict[str, Any] = Field(
        default_factory=dict,
        description="Collector-specific payload. Treated as untrusted input.",
    )

    @field_validator("host_id")
    @classmethod
    def validate_host_id(cls, v: str) -> str:
        if not _SAFE_ID_RE.match(v):
            raise ValueError(
                "host_id must contain only alphanumeric characters, hyphens, underscores, or dots"
            )
        return v

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if not _SAFE_ACTION_RE.match(v):
            raise ValueError(
                "action must contain only alphanumeric characters and underscores"
            )
        return v

    @field_validator("raw")
    @classmethod
    def limit_raw_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        # Prevent oversized payloads from exhausting memory during rule evaluation.
        # 50 keys is generous for any collector we plan to build.
        if len(v) > 50:
            raise ValueError("raw payload exceeds maximum allowed key count (50)")
        return v
