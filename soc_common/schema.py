"""The common log-event format.

Auth logs, web logs and firewall logs all look different. Analysts waste time
switching mental models, so the first job of a SOC pipeline is *normalisation*:
turn every source into the same small set of fields. Then one detector or one
timeline can work on all of them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict

OUTCOMES = ("success", "failure", "allow", "deny", "error", "unknown")


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into a timezone-aware UTC datetime.

    Naive timestamps (no offset) are assumed to be UTC. Raises ValueError
    with a readable message if the text cannot be parsed.
    """
    text = str(value).strip()
    if not text:
        raise ValueError("empty timestamp")
    if text.endswith("Z") or text.endswith("z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError("cannot parse timestamp %r (expected ISO format like 2026-10-28T02:14:03Z)" % value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    """Format a datetime as compact UTC ISO text, e.g. 2026-10-28T02:14:03Z."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class LogEvent:
    """One normalised log event."""

    timestamp: datetime
    source: str            # "auth", "web", "firewall" ...
    message: str           # short human-readable description
    host: str = ""
    user: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    action: str = ""       # e.g. ssh_login, web_login, http_request, firewall_connection
    outcome: str = "unknown"
    raw: str = ""          # the original line, kept as evidence
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": iso(self.timestamp),
            "source": self.source,
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "action": self.action,
            "outcome": self.outcome,
            "message": self.message,
            "raw": self.raw,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogEvent":
        if "timestamp" not in data:
            raise ValueError("event is missing the 'timestamp' field")
        return cls(
            timestamp=parse_timestamp(data["timestamp"]),
            source=str(data.get("source", "")),
            message=str(data.get("message", "")),
            host=str(data.get("host", "")),
            user=str(data.get("user", "")),
            src_ip=str(data.get("src_ip", "")),
            dst_ip=str(data.get("dst_ip", "")),
            action=str(data.get("action", "")),
            outcome=str(data.get("outcome", "unknown")),
            raw=str(data.get("raw", "")),
            extra=dict(data.get("extra") or {}),
        )
