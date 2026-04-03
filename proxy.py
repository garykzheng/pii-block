"""MCP Privacy Proxy — stdio entry point.

Creates a FastMCP proxy that wraps backend MCP server(s) with PII masking
middleware.

CLI usage (pass-through mode for .mcp.json integration):
    python proxy.py -- npx @playwright/mcp@latest --config config.json
    python proxy.py --backend-url http://localhost:3456/mcp
    python proxy.py --auth oauth --backend-url https://mcp.slack.com/mcp
    python proxy.py --auth oauth --oauth-client-id CLIENT_ID --backend-url https://mcp.slack.com/mcp

Environment variables (optional overrides):
    BACKEND_URL        — URL of the backend MCP server (SSE/HTTP)
    BACKEND_COMMAND    — Command to spawn a stdio backend (e.g. "python server.py")
    BACKEND_AUTH       — Auth mode: "oauth" for browser-based OAuth, or a bearer token
    FPE_KEY            — Hex-encoded 128/192/256-bit key for format-preserving encryption
    MAPPING_STORE_PATH — Path to JSON file for persisting PII mappings
                         (default: ~/Library/Application Support/mcp-privacy-proxy/mappings.json)
    CONFIG_PATH        — Path to policy YAML file (default: default_policy.yaml)
    SERVERS_PATH       — Path to servers.yaml (default: servers.yaml)

.mcp.json example:
    {
      "mcpServers": {
        "playwright": {
          "type": "stdio",
          "command": "python",
          "args": ["proxy.py", "--", "npx", "@playwright/mcp@latest"]
        },
        "pylon": {
          "type": "stdio",
          "command": "python",
          "args": ["proxy.py", "--auth", "oauth", "--backend-url", "https://mcp.usepylon.com/"]
        },
        "slack": {
          "type": "stdio",
          "command": "python",
          "args": ["proxy.py", "--auth", "oauth", "--oauth-client-id", "CLIENT_ID",
                   "--oauth-callback-port", "3118", "--backend-url", "https://mcp.slack.com/mcp"]
        }
      }
    }
"""

from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path

from audit import RemoteAuditLog
from config import load_policy, default_policy_path
from mapping_store import MappingStore, default_mapping_path
from server_registry import ServerRegistry
from core import build_proxy


def _parse_cli_args() -> dict:
    """Parse CLI arguments.

    Returns a dict with keys: backend_url, backend_command, auth,
    oauth_client_id, oauth_callback_port.
    """
    argv = sys.argv[1:]
    result = {
        "backend_url": None,
        "backend_command": None,
        "auth": None,
        "oauth_client_id": None,
        "oauth_callback_port": None,
    }

    # Check for -- pass-through: everything after -- is the backend command
    if "--" in argv:
        idx = argv.index("--")
        remaining = argv[idx + 1:]
        prefix = argv[:idx]
        if remaining:
            result["backend_command"] = " ".join(shlex.quote(a) for a in remaining)
        argv = prefix

    _FLAG_MAP = {
        "--backend-url": "backend_url",
        "--auth": "auth",
        "--oauth-client-id": "oauth_client_id",
        "--oauth-callback-port": "oauth_callback_port",
    }

    i = 0
    while i < len(argv):
        key = _FLAG_MAP.get(argv[i])
        if key and i + 1 < len(argv):
            result[key] = argv[i + 1]
            i += 2
        else:
            i += 1

    return result


def main() -> None:
    # ── --ensure-auth mode: just do OAuth and exit ────────────────────
    # Used internally as a subprocess to avoid event loop conflicts.
    if "--ensure-auth" in sys.argv:
        sys.argv.remove("--ensure-auth")
        cli = _parse_cli_args()
        backend_url = cli["backend_url"] or os.environ.get("BACKEND_URL")
        auth = cli["auth"] or os.environ.get("BACKEND_AUTH")
        if auth == "oauth" and backend_url:
            from core import _has_saved_tokens, _do_oauth_flow
            if not _has_saved_tokens(backend_url):
                port = int(cli["oauth_callback_port"]) if cli["oauth_callback_port"] else None
                _do_oauth_flow(backend_url, client_id=cli["oauth_client_id"], callback_port=port)
        return

    # ── CLI arguments (override env vars) ─────────────────────────────
    cli = _parse_cli_args()

    # ── Resolve configuration ─────────────────────────────────────────
    backend_url = cli["backend_url"] or os.environ.get("BACKEND_URL")
    backend_command = cli["backend_command"] or os.environ.get("BACKEND_COMMAND")
    auth = cli["auth"] or os.environ.get("BACKEND_AUTH")
    servers_path = os.environ.get("SERVERS_PATH", "servers.yaml")

    # ── Ensure OAuth tokens (runs in a subprocess) ────────────────────
    # On first use, this opens a browser for auth. Runs as a subprocess
    # so the event loop stays clean for the MCP server. Subsequent
    # starts find saved tokens and skip this instantly.
    if auth == "oauth" and backend_url:
        from core import _has_saved_tokens
        if not _has_saved_tokens(backend_url):
            ensure_cmd = [sys.executable, __file__, "--ensure-auth"] + sys.argv[1:]
            subprocess.run(ensure_cmd, check=True)

    fpe_key = os.environ.get(
        "FPE_KEY",
        # Default key for development only — override in production!
        "EF4359D8D580AA4F7F036D6F04FC6A94",
    )

    mapping_path = os.environ.get("MAPPING_STORE_PATH", str(default_mapping_path()))
    config_path = os.environ.get("CONFIG_PATH")
    if not config_path:
        # Priority: local override > data dir > bundled default
        local_policy = Path(__file__).parent / "policy.local.yaml"
        data_policy = default_policy_path()
        bundled_policy = Path(__file__).parent / "default_policy.yaml"
        if local_policy.exists():
            config_path = str(local_policy)
        elif data_policy.exists():
            config_path = str(data_policy)
        else:
            config_path = str(bundled_policy)

    # ── Load policy and mapping store ─────────────────────────────────
    policy = load_policy(config_path)
    mapping_store = MappingStore(path=mapping_path)

    # ── Build server registry ─────────────────────────────────────────
    # CLI args take priority, then servers.yaml, then env vars
    if backend_url:
        port = int(cli["oauth_callback_port"]) if cli["oauth_callback_port"] else None
        registry = ServerRegistry.from_single(
            backend_url, auth=auth,
            oauth_client_id=cli["oauth_client_id"],
            oauth_callback_port=port,
        )
    elif backend_command:
        registry = ServerRegistry.from_single(backend_command)
    elif Path(servers_path).exists():
        registry = ServerRegistry(path=servers_path)
    else:
        print(
            "Error: Provide a backend via -- command, --backend-url, "
            "BACKEND_URL, BACKEND_COMMAND, or create servers.yaml.",
            file=sys.stderr,
        )
        sys.exit(1)

    # ── Audit log (push to dashboard if running) ─────────────────────
    dashboard_url = os.environ.get("DASHBOARD_URL", "http://127.0.0.1:8080")
    audit_log = RemoteAuditLog(dashboard_url=dashboard_url)

    # ── Build and run proxy ───────────────────────────────────────────
    proxy = build_proxy(
        registry=registry,
        policy=policy,
        mapping_store=mapping_store,
        fpe_key=fpe_key,
        audit_log=audit_log,
    )

    proxy.run(transport="stdio")


if __name__ == "__main__":
    main()
