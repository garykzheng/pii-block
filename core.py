"""Core proxy builder shared by both stdio (proxy.py) and HTTP (server.py) modes.

Constructs a FastMCP proxy with PrivacyMiddleware and mounts all enabled
servers from the registry.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastmcp import FastMCP
from fastmcp.server import create_proxy

from middleware import PrivacyMiddleware

if TYPE_CHECKING:
    from audit import AuditLog
    from config import PolicyConfig
    from mapping_store import MappingStore
    from server_registry import ServerRegistry


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
        child = create_proxy(entry.target)
        parent.mount(child, namespace=name)

    return parent
