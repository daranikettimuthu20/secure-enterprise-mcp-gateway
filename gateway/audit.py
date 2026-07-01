"""
Structured JSON audit logging. Every tool call - whether allowed or blocked -
gets one line here, in a format that's trivial to ship to Splunk/ELK/Datadog.
"""
from __future__ import annotations
import json
import logging
import os
import sys
import datetime as dt
from pathlib import Path
from gateway.config import settings

_logger = logging.getLogger("mcp_gateway.audit")
_logger.setLevel(logging.INFO)

os.makedirs(Path(settings.AUDIT_LOG_PATH).parent, exist_ok=True)

_file_handler = logging.FileHandler(settings.AUDIT_LOG_PATH)
_file_handler.setFormatter(logging.Formatter("%(message)s"))
_logger.addHandler(_file_handler)

_stdout_handler = logging.StreamHandler(sys.stdout)
_stdout_handler.setFormatter(logging.Formatter("%(message)s"))
_logger.addHandler(_stdout_handler)


def log_event(
    *,
    principal_subject: str,
    role: str,
    upstream: str,
    tool_name: str,
    decision: str,          # "allowed" | "blocked"
    blocked_by: str | None,  # "policy" | "injection_scanner" | "pii_scanner" | None
    findings: list[dict],
    latency_ms: float | None = None,
) -> None:
    record = {
        "timestamp": dt.datetime.utcnow().isoformat() + "Z",
        "subject": principal_subject,
        "role": role,
        "upstream": upstream,
        "tool_name": tool_name,
        "decision": decision,
        "blocked_by": blocked_by,
        "findings": findings,
        "latency_ms": latency_ms,
    }
    _logger.info(json.dumps(record))
