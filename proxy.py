"""MCP Privacy Proxy — stdio entry point.

Creates a FastMCP proxy that wraps backend MCP server(s) with PII masking
middleware.

CLI usage (pass-through mode for .mcp.json integration):
    python proxy.py -- npx @playwright/mcp@latest --config config.json
    python proxy.py --backend-url http://localhost:3456/mcp
    python proxy.py --auth oauth --backend-url https://mcp.slack.com/mcp

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
        "slack": {
          "type": "stdio",
          "command": "python",
          "args": ["proxy.py", "--auth", "oauth", "--backend-url", "https://mcp.slack.com/mcp"]
        }
      }
    }
"""

from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

from audit import RemoteAuditLog
from config import load_policy, default_policy_path
from mapping_store import MappingStore, default_mapping_path
from server_registry import ServerRegistry
from core import build_proxy


def _parse_cli_args() -> tuple[str | None, str | None, str | None]:
    """Parse CLI arguments for --backend-url, --auth, and -- pass-through command.

    Returns (backend_url, backend_command, auth) from CLI args, or (None, None, None)
    if no CLI args were provided.
    """
    argv = sys.argv[1:]
    backend_url = None
    backend_command = None
    auth = None

    # Check for -- pass-through: everything after -- is the backend command
    if "--" in argv:
        idx = argv.index("--")
        remaining = argv[idx + 1:]
        prefix = argv[:idx]
        if remaining:
            backend_command = " ".join(shlex.quote(a) for a in remaining)
        argv = prefix

    # Check for --backend-url and --auth
    i = 0
    while i < len(argv):
        if argv[i] == "--backend-url" and i + 1 < len(argv):
            backend_url = argv[i + 1]
            i += 2
        elif argv[i] == "--auth" and i + 1 < len(argv):
            auth = argv[i + 1]
            i += 2
        else:
            i += 1

    return backend_url, backend_command, auth


def _ensure_auth(backend_url: str) -> None:
    """Ensure OAuth tokens exist for the backend, running the browser flow if needed.

    Called as a separate step before the proxy starts so that the OAuth
    browser flow (which can take minutes) doesn't block the MCP stdio
    server from responding to Claude Code's initialize message.
    """
    from core import _has_saved_tokens, _do_oauth_flow
    if not _has_saved_tokens(backend_url):
        _do_oauth_flow(backend_url)


def main() -> None:
    # ── --ensure-auth mode: just do OAuth and exit ────────────────────
    if "--ensure-auth" in sys.argv:
        sys.argv.remove("--ensure-auth")
        cli_url, cli_command, cli_auth = _parse_cli_args()
        backend_url = cli_url or os.environ.get("BACKEND_URL")
        auth = cli_auth or os.environ.get("BACKEND_AUTH")
        if auth == "oauth" and backend_url:
            _ensure_auth(backend_url)
        return

    # ── CLI arguments (override env vars) ─────────────────────────────
    cli_url, cli_command, cli_auth = _parse_cli_args()

    # ── Resolve configuration ─────────────────────────────────────────
    backend_url = cli_url or os.environ.get("BACKEND_URL")
    backend_command = cli_command or os.environ.get("BACKEND_COMMAND")
    auth = cli_auth or os.environ.get("BACKEND_AUTH")
    servers_path = os.environ.get("SERVERS_PATH", "servers.yaml")

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
        registry = ServerRegistry.from_single(backend_url, auth=auth)
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
