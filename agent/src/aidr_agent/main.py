from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timezone

import requests

from .config import AgentConfig, load_config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("aidr.agent")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def emit(event: dict, config: AgentConfig) -> None:
    """
    POST a single event to the backend ingest endpoint.

    Failures are logged as warnings but never crash the agent — a temporarily
    unavailable backend should not stop collection. Events dropped during an
    outage are lost in Phase 1; a local queue is a Phase 6 concern.

    Security: the API key is sent as a header, never as a query parameter
    (query params appear in access logs on proxies and load balancers).
    """
    try:
        resp = requests.post(
            config.ingest_url,
            json=event,
            headers={"X-API-Key": config.api_key},
            timeout=5,
        )
        if resp.status_code not in (200, 202):
            logger.warning(
                "ingest rejected status=%d host_id=%s action=%s",
                resp.status_code,
                event.get("host_id"),
                event.get("action"),
            )
    except requests.Timeout:
        logger.warning("emit timed out host_id=%s", event.get("host_id"))
    except requests.ConnectionError as exc:
        logger.warning("emit connection error: %s", exc)


def tail_file(path: str):
    """
    Yield new lines appended to `path` in real time (tail -f equivalent).

    Opens the file in text mode with error replacement so malformed bytes in
    a log file do not crash the agent.
    """
    with open(path, "r", errors="ignore") as f:
        f.seek(0, 2)  # seek to end — ignore historical entries on startup
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.25)
                continue
            yield line.strip()


def parse_auth_line(line: str) -> dict | None:
    """
    Extract a structured event from a single syslog auth line.

    Returns None for lines that don't match any known pattern so the caller
    can skip them cleanly.
    """
    lower = line.lower()

    if "failed password" in lower:
        return {"event_type": "auth", "action": "login_fail", "raw": {"line": line}}

    if "accepted password" in lower or "accepted publickey" in lower:
        return {"event_type": "auth", "action": "ssh_login_success", "raw": {"line": line}}

    if "sudo:" in lower and "authentication failure" in lower:
        return {"event_type": "auth", "action": "sudo_fail", "raw": {"line": line}}

    if "sudo:" in lower and "command=" in lower:
        return {"event_type": "auth", "action": "sudo_success", "raw": {"line": line}}

    return None


def main() -> None:
    config = load_config()

    logger.info(
        "agent starting host_id=%s ingest=%s auth_log=%s",
        config.host_id,
        config.ingest_url,
        config.auth_log,
    )

    if not os.path.exists(config.auth_log):
        logger.error("auth log not found: %s — is this Ubuntu with sshd running?", config.auth_log)
        raise SystemExit(1)

    for line in tail_file(config.auth_log):
        parsed = parse_auth_line(line)
        if not parsed:
            continue

        event = {
            "ts": now_iso(),
            "host_id": config.host_id,
            "event_type": parsed["event_type"],
            "action": parsed["action"],
            "raw": parsed["raw"],
        }
        emit(event, config)


if __name__ == "__main__":
    main()
