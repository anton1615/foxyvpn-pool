"""Logging setup: debug/info/warn/error levels and text or JSON output,
always written to stderr.
"""

from __future__ import annotations

import json
import logging
import sys
import time

LOG_LEVELS = {"debug": logging.DEBUG, "info": logging.INFO, "warn": logging.WARNING, "error": logging.ERROR}


def _rfc3339_timestamp(created: float) -> str:
    """Format ``created`` (a ``time.time()``-style epoch float) as a proper
    RFC 3339 timestamp with a colon-separated UTC offset (e.g.
    ``2024-01-02T15:04:05+03:30``), matching Go's ``time.RFC3339``. Python's
    bare ``%z`` omits the colon (``+0330``), which is not valid RFC 3339.
    """
    local = time.localtime(created)
    base = time.strftime("%Y-%m-%dT%H:%M:%S", local)
    offset = time.strftime("%z", local)
    if len(offset) == 5:
        offset = f"{offset[:3]}:{offset[3:]}"
    elif not offset:
        offset = "+00:00"
    return base + offset


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": _rfc3339_timestamp(record.created),
            "level": record.levelname.lower(),
            "message": record.getMessage(),
        }
        return json.dumps(payload)


class _TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = _rfc3339_timestamp(record.created)
        return f"{ts} {record.levelname.lower():<5} {record.getMessage()}"


def parse_log_level(value: str) -> int:
    level = LOG_LEVELS.get(value.strip().lower())
    if level is None:
        raise ValueError(f"invalid log level {value!r} (expected one of: {', '.join(LOG_LEVELS)})")
    return level


def parse_log_format(value: str) -> str:
    fmt = value.strip().lower()
    if fmt not in ("text", "json"):
        raise ValueError(f"invalid log format {value!r} (expected 'text' or 'json')")
    return fmt


def configure_logger(level: str = "info", fmt: str = "text") -> None:
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(_JsonFormatter() if parse_log_format(fmt) == "json" else _TextFormatter())
    root = logging.getLogger("foxyvpn")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(parse_log_level(level))
    root.propagate = False
