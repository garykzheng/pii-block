"""Server registry for managing multiple MCP backend servers.

Persists server configuration to a YAML file. Each server has a target
(URL or command string), an enabled flag, and a timestamp.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ServerEntry:
    """A single MCP backend server."""
    target: str
    enabled: bool = True
    added_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    auth: str | None = None  # "oauth" or a bearer token string
    headers: dict[str, str] | None = None  # custom headers (e.g. API keys)


class ServerRegistry:
    """Manages a collection of MCP backend servers with YAML persistence."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._servers: dict[str, ServerEntry] = {}
        if self._path and self._path.exists():
            self.load(self._path)

    @classmethod
    def from_single(cls, target: str, name: str = "default") -> ServerRegistry:
        """Create a registry with a single server (backwards compat with env vars)."""
        registry = cls()
        registry._servers[name] = ServerEntry(target=target)
        return registry

    def load(self, path: str | Path | None = None) -> None:
        """Load servers from a YAML file."""
        p = Path(path) if path else self._path
        if not p or not p.exists():
            return
        self._path = p
        with p.open() as f:
            raw: dict[str, Any] = yaml.safe_load(f) or {}
        self._servers = {}
        for name, cfg in (raw.get("servers") or {}).items():
            self._servers[name] = ServerEntry(
                target=cfg["target"],
                enabled=cfg.get("enabled", True),
                added_at=cfg.get("added_at", datetime.now(timezone.utc).isoformat()),
                auth=cfg.get("auth"),
                headers=cfg.get("headers"),
            )

    def save(self) -> None:
        """Persist servers to the YAML file."""
        if not self._path:
            return
        data: dict[str, Any] = {"servers": {}}
        for name, entry in self._servers.items():
            d: dict[str, Any] = {
                "target": entry.target,
                "enabled": entry.enabled,
                "added_at": entry.added_at,
            }
            if entry.auth is not None:
                d["auth"] = entry.auth
            if entry.headers is not None:
                d["headers"] = entry.headers
            data["servers"][name] = d
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def add(self, name: str, target: str, enabled: bool = True) -> None:
        """Add a new server."""
        if name in self._servers:
            raise ValueError(f"Server '{name}' already exists")
        self._servers[name] = ServerEntry(target=target, enabled=enabled)
        self.save()

    def remove(self, name: str) -> None:
        """Remove a server by name."""
        if name not in self._servers:
            raise KeyError(f"Server '{name}' not found")
        del self._servers[name]
        self.save()

    def enable(self, name: str) -> None:
        """Enable a server."""
        if name not in self._servers:
            raise KeyError(f"Server '{name}' not found")
        self._servers[name].enabled = True
        self.save()

    def disable(self, name: str) -> None:
        """Disable a server."""
        if name not in self._servers:
            raise KeyError(f"Server '{name}' not found")
        self._servers[name].enabled = False
        self.save()

    def set_auth(
        self,
        name: str,
        auth: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        """Set auth and/or headers for a server."""
        if name not in self._servers:
            raise KeyError(f"Server '{name}' not found")
        if auth is not None:
            self._servers[name].auth = auth
        if headers is not None:
            self._servers[name].headers = headers
        self.save()

    def clear_auth(self, name: str) -> None:
        """Remove auth config from a server."""
        if name not in self._servers:
            raise KeyError(f"Server '{name}' not found")
        self._servers[name].auth = None
        self._servers[name].headers = None
        self.save()

    def enabled_servers(self) -> dict[str, ServerEntry]:
        """Return only enabled servers."""
        return {n: s for n, s in self._servers.items() if s.enabled}

    def all_servers(self) -> dict[str, ServerEntry]:
        """Return all servers."""
        return dict(self._servers)

    def get(self, name: str) -> ServerEntry | None:
        """Get a server by name."""
        return self._servers.get(name)

    def __len__(self) -> int:
        return len(self._servers)
