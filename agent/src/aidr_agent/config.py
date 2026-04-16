from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class AgentConfig:
    host_id: str
    ingest_url: str
    api_key: str
    auth_log: str
    network_poll_seconds: int
    file_check_seconds: int


def load_config() -> AgentConfig:
    """
    Load agent configuration from environment variables.

    Fails fast with a clear error message if required variables are missing.
    Callers should never catch this exception — a misconfigured agent should
    not silently start sending unauthenticated or misdirected telemetry.

    Required:
        AGENT_HOST_ID       — unique identifier for this endpoint (e.g. "ubuntu-lab-01")
        AGENT_INGEST_URL    — full URL of the backend ingest endpoint
        AGENT_API_KEY       — shared secret sent as X-API-Key header

    Optional:
        AGENT_AUTH_LOG           — path to auth log (default: /var/log/auth.log)
        AGENT_NETWORK_POLL       — network collector poll interval in seconds (default: 30)
        AGENT_FILE_CHECK_SECONDS — filesystem check interval in seconds (default: 60)
    """
    host_id = os.environ.get("AGENT_HOST_ID", "").strip()
    ingest_url = os.environ.get("AGENT_INGEST_URL", "").strip()
    api_key = os.environ.get("AGENT_API_KEY", "").strip()

    missing = [
        name
        for name, value in [
            ("AGENT_HOST_ID", host_id),
            ("AGENT_INGEST_URL", ingest_url),
            ("AGENT_API_KEY", api_key),
        ]
        if not value
    ]
    if missing:
        raise EnvironmentError(
            f"Missing required environment variables: {', '.join(missing)}\n"
            "Copy .env.sample to .env and fill in all required values."
        )

    try:
        network_poll = int(os.environ.get("AGENT_NETWORK_POLL", "30"))
        file_check = int(os.environ.get("AGENT_FILE_CHECK_SECONDS", "60"))
    except ValueError as exc:
        raise EnvironmentError(f"Invalid interval value in environment: {exc}") from exc

    return AgentConfig(
        host_id=host_id,
        ingest_url=ingest_url,
        api_key=api_key,
        auth_log=os.environ.get("AGENT_AUTH_LOG", "/var/log/auth.log").strip(),
        network_poll_seconds=network_poll,
        file_check_seconds=file_check,
    )
