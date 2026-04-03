"""Core proxy builder shared by both stdio (proxy.py) and HTTP (server.py) modes.

Constructs a FastMCP proxy with PrivacyMiddleware and mounts all enabled
servers from the registry.
"""

from __future__ import annotations

import asyncio
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


def _get_token_store():
    """Get the shared FileTreeStore for OAuth token persistence."""
    from key_value.aio.stores.filetree.store import (
        FileTreeStore,
        FileTreeV1CollectionSanitizationStrategy,
        FileTreeV1KeySanitizationStrategy,
    )
    return FileTreeStore(
        data_directory=_DEFAULT_TOKEN_DIR,
        key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(
            _DEFAULT_TOKEN_DIR,
        ),
        collection_sanitization_strategy=FileTreeV1CollectionSanitizationStrategy(
            _DEFAULT_TOKEN_DIR,
        ),
    )


def _has_saved_tokens(url: str) -> bool:
    """Check if OAuth tokens already exist on disk for the given URL."""
    from fastmcp.client.auth.oauth import TokenStorageAdapter
    store = _get_token_store()
    adapter = TokenStorageAdapter(async_key_value=store, server_url=url.rstrip("/"))
    # Run the async check synchronously during startup
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Already in an async context — can't nest; assume no tokens
            return False
        return loop.run_until_complete(adapter.get_tokens()) is not None
    except RuntimeError:
        return asyncio.run(adapter.get_tokens()) is not None


def _build_oauth(
    url: str,
    client_id: str | None = None,
    callback_port: int | None = None,
):
    """Build an OAuth instance with persistent file-based token storage."""
    from fastmcp.client.auth.oauth import OAuth
    kwargs: dict = {"mcp_url": url, "token_storage": _get_token_store()}
    if client_id:
        kwargs["client_id"] = client_id
    if callback_port:
        kwargs["callback_port"] = callback_port
    return OAuth(**kwargs)


def _do_oauth_flow(
    url: str,
    client_id: str | None = None,
    callback_port: int | None = None,
) -> None:
    """Run the OAuth browser flow synchronously and save tokens to disk.

    Opens a browser for authorization, waits for the callback, exchanges
    the code for tokens, and persists them via the FileTreeStore. Blocks
    until the flow completes (up to 5 minutes).
    """
    import sys
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    print(f"[pii-proxy] No saved OAuth tokens for {url}", file=sys.stderr)
    print(f"[pii-proxy] Opening browser for authentication...", file=sys.stderr)

    oauth = _build_oauth(url, client_id=client_id, callback_port=callback_port)
    transport = StreamableHttpTransport(url=url, auth=oauth)

    async def _auth():
        async with Client(transport=transport, timeout=300) as client:
            tools = await client.list_tools()
        return len(tools)

    n = asyncio.run(_auth())
    print(f"[pii-proxy] Authenticated! Found {n} tools.", file=sys.stderr)


def _parse_target(
    target: str,
    auth: str | None = None,
    headers: dict[str, str] | None = None,
    oauth_client_id: str | None = None,
    oauth_callback_port: int | None = None,
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
            kwargs["auth"] = _build_oauth(
                target, client_id=oauth_client_id, callback_port=oauth_callback_port,
            )
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

    OAuth tokens should be obtained before calling this function (see
    ``proxy.py``'s ``_ensure_auth``). The proxy connects to backends
    using saved tokens.
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
            oauth_client_id=entry.oauth_client_id,
            oauth_callback_port=entry.oauth_callback_port,
        )
        child = create_proxy(transport)

        # Single server: don't namespace, so tool names pass through unchanged
        if len(enabled) == 1:
            parent.mount(child)
        else:
            parent.mount(child, namespace=name)

    return parent
