"""Core proxy builder shared by both stdio (proxy.py) and HTTP (server.py) modes.

Constructs a FastMCP proxy with PrivacyMiddleware and mounts all enabled
servers from the registry.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import TYPE_CHECKING

from fastmcp import FastMCP
from fastmcp.client.transports import NodeStdioTransport, PythonStdioTransport
from fastmcp.client.transports.stdio import NpxStdioTransport
from fastmcp.server import create_proxy

from middleware import PrivacyMiddleware

if TYPE_CHECKING:
    from audit import AuditLog
    from config import PolicyConfig
    from mapping_store import MappingStore
    from server_registry import ServerRegistry

_DEFAULT_TOKEN_DIR = (
    Path.home() / "Library" / "Application Support" / "mcp-privacy-proxy" / "oauth"
)


def _build_oauth(url: str):
    """Build an OAuth instance with persistent file-based token storage."""
    from fastmcp.client.auth.oauth import OAuth
    from key_value.aio.stores.filetree.store import FileTreeStore

    store = FileTreeStore(data_directory=_DEFAULT_TOKEN_DIR)
    return OAuth(mcp_url=url, token_storage=store)


def _parse_target(
    target: str,
    auth: str | None = None,
    headers: dict[str, str] | None = None,
):
    """Convert a target string into a transport that FastMCP understands.

    Handles:
    - URLs (http://, https://) — creates StreamableHttpTransport with auth
    - File paths ending in .py or .js — passed through as-is
    - Command strings (e.g. "node mcp/index.js") — parsed into the
      appropriate stdio transport
    """
    # URLs: create HTTP transport with auth support
    if target.startswith(("http://", "https://")):
        from fastmcp.client.transports import StreamableHttpTransport
        kwargs: dict = {"url": target}
        if auth == "oauth":
            kwargs["auth"] = _build_oauth(target)
        elif auth is not None:
            kwargs["auth"] = auth
        if headers is not None:
            kwargs["headers"] = headers
        return StreamableHttpTransport(**kwargs)

    parts = shlex.split(target)

    # Single file path: pass through
    if len(parts) == 1 and (parts[0].endswith(".py") or parts[0].endswith(".js")):
        return target

    # Command string: parse into stdio transport
    cmd = parts[0]
    args = parts[1:]

    if cmd == "npx":
        if not args:
            raise ValueError(f"npx command needs a package name: {target}")
        return NpxStdioTransport(package=args[0], args=args[1:])

    if cmd == "node":
        if not args:
            raise ValueError(f"Node command needs a script: {target}")
        return NodeStdioTransport(script_path=args[0], args=args[1:])

    if cmd == "python" or cmd == "python3":
        if not args:
            raise ValueError(f"Python command needs a script: {target}")
        return PythonStdioTransport(script_path=args[0], args=args[1:], python_cmd=cmd)

    # For other commands, try npx-style if it looks like a package name,
    # otherwise fall back to letting FastMCP figure it out
    return target


def build_proxy(
    registry: ServerRegistry,
    policy: PolicyConfig,
    mapping_store: MappingStore,
    fpe_key: str,
    audit_log: AuditLog | None = None,
) -> FastMCP:
    """Build a FastMCP proxy with privacy middleware over all enabled servers.

    Returns a FastMCP instance with:
    - PrivacyMiddleware attached (applies to all mounted children)
    - Each enabled server from the registry mounted under its name
    """
    parent = FastMCP("MCP Privacy Proxy")

    # Attach privacy middleware to the parent — it applies to all children
    middleware = PrivacyMiddleware(
        policy=policy,
        mapping_store=mapping_store,
        fpe_key=fpe_key,
        audit_log=audit_log,
    )
    parent.add_middleware(middleware)

    # Mount each enabled server
    enabled = registry.enabled_servers()
    for name, entry in enabled.items():
        transport = _parse_target(
            entry.target, auth=entry.auth, headers=entry.headers,
        )
        child = create_proxy(transport)

        # Single server: don't namespace, so tool names pass through unchanged
        if len(enabled) == 1:
            parent.mount(child)
        else:
            parent.mount(child, namespace=name)

    return parent
