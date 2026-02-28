"""MCP Privacy Proxy — stdio entry point.

Creates a FastMCP proxy that wraps backend MCP server(s) with PII masking
middleware. Configurable via environment variables:

    BACKEND_URL       — URL of the backend MCP server (SSE/HTTP)
    BACKEND_COMMAND   — Command to spawn a stdio backend (e.g. "python server.py")
    FPE_KEY           — Hex-encoded 128/192/256-bit key for format-preserving encryption
    MAPPING_STORE_PATH — Path to JSON file for persisting PII mappings (default: mappings.json)
    CONFIG_PATH       — Path to policy YAML file (default: default_policy.yaml)
    SERVERS_PATH      — Path to servers.yaml (default: servers.yaml)

Usage:
    python proxy.py                           # uses env vars
    claude mcp add my-proxy -- python proxy.py  # register with Claude Code
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from config import load_policy
from mapping_store import MappingStore
from server_registry import ServerRegistry
from core import build_proxy


def main() -> None:
    # ── Resolve configuration ─────────────────────────────────────────
    backend_url = os.environ.get("BACKEND_URL")
    backend_command = os.environ.get("BACKEND_COMMAND")
    servers_path = os.environ.get("SERVERS_PATH", "servers.yaml")

    fpe_key = os.environ.get(
        "FPE_KEY",
        # Default key for development only — override in production!
        "EF4359D8D580AA4F7F036D6F04FC6A94",
    )

    mapping_path = os.environ.get("MAPPING_STORE_PATH", "mappings.json")
    config_path = os.environ.get(
        "CONFIG_PATH",
        str(Path(__file__).parent / "default_policy.yaml"),
    )

    # ── Load policy and mapping store ─────────────────────────────────
    policy = load_policy(config_path)
    mapping_store = MappingStore(path=mapping_path)

    # ── Build server registry ─────────────────────────────────────────
    if Path(servers_path).exists():
        registry = ServerRegistry(path=servers_path)
    elif backend_url:
        registry = ServerRegistry.from_single(backend_url)
    elif backend_command:
        registry = ServerRegistry.from_single(backend_command)
    else:
        print(
            "Error: Set BACKEND_URL, BACKEND_COMMAND, or create servers.yaml.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Build and run proxy ───────────────────────────────────────────
    proxy = build_proxy(
        registry=registry,
        policy=policy,
        mapping_store=mapping_store,
        fpe_key=fpe_key,
    )

    proxy.run(transport="stdio")


if __name__ == "__main__":
    main()
