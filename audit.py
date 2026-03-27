"""Audit log for PII transformation events.

AuditLog: in-memory ring buffer used by the dashboard server.
RemoteAuditLog: fire-and-forget HTTP client used by stdio proxy instances
    to push events to the dashboard. Silently drops events if the dashboard
    isn't running.
"""

from __future__ import annotations

import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("audit")


@dataclass
class AuditEvent:
    """A single PII transformation event."""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    server: str = ""
    tool_name: str = ""
    direction: str = ""  # "mask" or "demap"
    entity_types: list[str] = field(default_factory=list)
    masked_count: int = 0
    demapped_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "server": self.server,
            "tool_name": self.tool_name,
            "direction": self.direction,
            "entity_types": self.entity_types,
            "masked_count": self.masked_count,
            "demapped_count": self.demapped_count,
        }


class AuditLog:
    """In-memory ring buffer of audit events."""

    def __init__(self, maxlen: int = 1000) -> None:
        self._events: deque[AuditEvent] = deque(maxlen=maxlen)

    def record(self, event: AuditEvent) -> None:
        """Add an event to the log."""
        self._events.append(event)

    def recent(self, n: int = 50) -> list[AuditEvent]:
        """Return the most recent n events (newest first)."""
        items = list(self._events)
        items.reverse()
        return items[:n]

    def stats(self) -> dict[str, Any]:
        """Compute summary statistics over all events."""
        total = len(self._events)
        total_masked = sum(e.masked_count for e in self._events)
        total_demapped = sum(e.demapped_count for e in self._events)

        entity_counts: dict[str, int] = {}
        tool_counts: dict[str, int] = {}
        server_counts: dict[str, int] = {}

        for event in self._events:
            for et in event.entity_types:
                entity_counts[et] = entity_counts.get(et, 0) + 1
            if event.tool_name:
                tool_counts[event.tool_name] = tool_counts.get(event.tool_name, 0) + 1
            if event.server:
                server_counts[event.server] = server_counts.get(event.server, 0) + 1

        return {
            "total_events": total,
            "total_masked": total_masked,
            "total_demapped": total_demapped,
            "entity_type_counts": entity_counts,
            "tool_counts": tool_counts,
            "server_counts": server_counts,
        }

    def to_json(self) -> list[dict[str, Any]]:
        """Serialize all events as a list of dicts."""
        return [e.to_dict() for e in self._events]

    def __len__(self) -> int:
        return len(self._events)


class RemoteAuditLog:
    """Fire-and-forget HTTP client that pushes audit events to the dashboard.

    If the dashboard isn't running, events are silently dropped.
    Sends are done in background threads to avoid blocking tool calls.
    """

    def __init__(self, dashboard_url: str = "http://127.0.0.1:8080") -> None:
        self._url = f"{dashboard_url.rstrip('/')}/api/audit/ingest"

    def record(self, event: AuditEvent) -> None:
        """Post an event to the dashboard in a background thread."""
        threading.Thread(target=self._send, args=(event,), daemon=True).start()

    def _send(self, event: AuditEvent) -> None:
        import json
        body = json.dumps(event.to_dict()).encode()
        req = Request(self._url, data=body, headers={"Content-Type": "application/json"})
        try:
            urlopen(req, timeout=1)
        except (URLError, OSError):
            pass
