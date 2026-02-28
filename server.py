"""MCP Privacy Proxy — HTTP entry point with management dashboard.

Runs a Starlette app on localhost:8080 that serves:
  - Dashboard UI for monitoring and managing the proxy
  - MCP protocol endpoint at /mcp for client connections

Configurable via the same environment variables as proxy.py, plus:
    HOST — bind address (default: 127.0.0.1)
    PORT — listen port (default: 8080)
    SERVERS_PATH — path to servers.yaml (default: servers.yaml)

Usage:
    python server.py
"""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn
from starlette.applications import Starlette

from audit import AuditLog
from config import load_policy
from core import build_proxy
from dashboard import create_dashboard_routes
from mapping_store import MappingStore
from middleware import PrivacyMiddleware
from server_registry import ServerRegistry


def main() -> None:
    # ── Configuration ─────────────────────────────────────────────────
    fpe_key = os.environ.get(
        "FPE_KEY",
        "EF4359D8D580AA4F7F036D6F04FC6A94",
    )
    mapping_path = os.environ.get("MAPPING_STORE_PATH", "mappings.json")
    config_path = os.environ.get(
        "CONFIG_PATH",
        str(Path(__file__).parent / "default_policy.yaml"),
    )
    servers_path = os.environ.get("SERVERS_PATH", "servers.yaml")
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))

    # ── Shared state ──────────────────────────────────────────────────
    policy = load_policy(config_path)
    mapping_store = MappingStore(path=mapping_path)
    audit_log = AuditLog()

    # Load or create server registry
    registry_path = Path(servers_path)
    if registry_path.exists():
        registry = ServerRegistry(path=registry_path)
    else:
        registry = ServerRegistry(path=registry_path)
        # Start with empty registry — user adds servers via dashboard

    # ── Build proxy ───────────────────────────────────────────────────
    proxy = build_proxy(
        registry=registry,
        policy=policy,
        mapping_store=mapping_store,
        fpe_key=fpe_key,
        audit_log=audit_log,
    )

    # Get a reference to the middleware for hot-reload
    mw_instance = None
    for mw in proxy.middleware:
        if isinstance(mw, PrivacyMiddleware):
            mw_instance = mw
            break

    # ── Compose Starlette app ─────────────────────────────────────────
    dashboard_routes = create_dashboard_routes(
        registry=registry,
        policy=policy,
        mapping_store=mapping_store,
        audit_log=audit_log,
        config_path=config_path,
        middleware=mw_instance,
    )

    # Mount MCP endpoint under /mcp
    mcp_app = proxy.http_app(path="/mcp")

    app = Starlette(
        routes=dashboard_routes,
    )
    app.mount("/mcp", mcp_app)

    # ── Run ───────────────────────────────────────────────────────────
    print(f"MCP Privacy Proxy dashboard: http://{host}:{port}")
    print(f"MCP endpoint: http://{host}:{port}/mcp")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
