"""HTTP reverse proxy that sits between Claude Code and remote MCP servers.

Unlike the stdio proxy (proxy.py) which wraps MCP servers as a FastMCP
middleware, this module is a thin HTTP reverse proxy. It forwards all
requests/responses transparently — including OAuth 401 flows — and only
intercepts JSON-RPC responses to apply PII masking on tool results.

Because it runs as a standard HTTP server, Claude Code sees it as a
``type: "http"`` MCP server and handles OAuth natively, showing the
proper "needs authentication" UI in the /mcp dialog.

Usage:
    python http_proxy.py --port 9001 --backend-url https://mcp.usepylon.com/

.mcp.json example:
    {
      "mcpServers": {
        "pylon": {
          "type": "http",
          "url": "http://localhost:9001/"
        }
      }
    }

Multi-backend mode (reads backends from servers.yaml):
    python http_proxy.py --port 9001

    With servers.yaml containing path-based routing:
        servers:
          pylon:
            target: https://mcp.usepylon.com/
          slack:
            target: https://mcp.slack.com/mcp

    Then in .mcp.json:
        "pylon": { "type": "http", "url": "http://localhost:9001/pylon" }
        "slack": { "type": "http", "url": "http://localhost:9001/slack" }
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from pathlib import Path

import httpx
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route, Mount

from config import load_policy, default_policy_path
from mapping_store import MappingStore, default_mapping_path
from middleware import PrivacyMiddleware

logger = logging.getLogger("http_proxy")

# Headers that should NOT be forwarded between client and backend.
_HOP_BY_HOP = frozenset({
    "transfer-encoding", "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers", "upgrade",
    "content-length",  # recalculated after PII masking may change body size
    "host",  # set to backend host
})


def _build_middleware(policy_path: str, mapping_path: str, fpe_key: str) -> PrivacyMiddleware:
    policy = load_policy(policy_path)
    mapping_store = MappingStore(path=mapping_path)
    return PrivacyMiddleware(
        policy=policy,
        mapping_store=mapping_store,
        fpe_key=fpe_key,
    )


def _mask_jsonrpc_response(body: bytes, mw: PrivacyMiddleware) -> bytes:
    """Apply PII masking to JSON-RPC tool call results in an MCP response.

    Only modifies ``tools/call`` responses — everything else passes through
    unchanged. Handles both single responses and batches.
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return body

    def _mask_single(msg: dict) -> dict:
        # Only mask tool call results (method response with content array)
        result = msg.get("result")
        if not isinstance(result, dict):
            return msg
        content = result.get("content")
        if not isinstance(content, list):
            return msg

        masked_content = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item.get("text", "")
                masked = mw._mask_text(text)
                masked_content.append({**item, "text": masked})
            else:
                masked_content.append(item)

        return {**msg, "result": {**result, "content": masked_content}}

    if isinstance(data, list):
        masked = [_mask_single(m) if isinstance(m, dict) else m for m in data]
    elif isinstance(data, dict):
        masked = _mask_single(data)
    else:
        return body

    return json.dumps(masked, ensure_ascii=False).encode()


def _rewrite_www_authenticate(header: str, proxy_origin: str, prefix: str) -> str:
    """Rewrite resource_metadata URLs in WWW-Authenticate to point to proxy."""
    # Replace resource_metadata="https://backend/.well-known/..."
    # with resource_metadata="http://localhost:PORT/prefix/.well-known/..."
    return re.sub(
        r'resource_metadata="[^"]*"',
        f'resource_metadata="{proxy_origin}{prefix}/.well-known/oauth-protected-resource"',
        header,
    )


def _rewrite_resource_metadata(body: bytes, proxy_origin: str, prefix: str) -> bytes:
    """Rewrite the 'resource' field in OAuth protected resource metadata."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return body
    if isinstance(data, dict) and "resource" in data:
        data["resource"] = f"{proxy_origin}{prefix}"
    return json.dumps(data, ensure_ascii=False).encode()


def _create_proxy_route(backend_url: str, mw: PrivacyMiddleware, prefix: str = ""):
    """Create a Starlette endpoint that reverse-proxies to a backend."""
    # Normalize: strip trailing slash from backend
    backend = backend_url.rstrip("/")

    async def proxy_endpoint(request: Request) -> Response:
        # Build the backend URL, appending any sub-path after the prefix
        path = request.url.path
        if prefix:
            path = path[len(prefix):]
        target_url = f"{backend}{path}"
        if request.url.query:
            target_url += f"?{request.url.query}"

        # Proxy origin as seen by the client (for OAuth URL rewriting)
        proxy_origin = f"{request.url.scheme}://{request.url.netloc}"

        # Forward headers (skip hop-by-hop)
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_BY_HOP
        }
        headers["host"] = httpx.URL(backend).host

        body = await request.body()

        async with httpx.AsyncClient(follow_redirects=False) as client:
            backend_resp = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                timeout=120.0,
            )

        # Forward response headers (skip hop-by-hop)
        resp_headers = {
            k: v for k, v in backend_resp.headers.items()
            if k.lower() not in _HOP_BY_HOP
        }

        resp_body = backend_resp.content

        # Rewrite OAuth URLs so Claude Code's SDK accepts the proxy origin
        if backend_resp.status_code == 401 and "www-authenticate" in resp_headers:
            resp_headers["www-authenticate"] = _rewrite_www_authenticate(
                resp_headers["www-authenticate"], proxy_origin, prefix,
            )

        # Rewrite protected resource metadata
        content_type = backend_resp.headers.get("content-type", "")
        if "oauth-protected-resource" in request.url.path and "json" in content_type:
            resp_body = _rewrite_resource_metadata(resp_body, proxy_origin, prefix)

        # Apply PII masking on successful JSON-RPC responses
        if (
            backend_resp.status_code == 200
            and "json" in content_type
            and resp_body
            and "oauth-protected-resource" not in request.url.path
        ):
            resp_body = _mask_jsonrpc_response(resp_body, mw)

        return Response(
            content=resp_body,
            status_code=backend_resp.status_code,
            headers=resp_headers,
        )

    return proxy_endpoint


def create_app(
    backend_url: str | None = None,
    backends: dict[str, str] | None = None,
    middleware: PrivacyMiddleware | None = None,
    policy_path: str | None = None,
    mapping_path: str | None = None,
    fpe_key: str | None = None,
) -> Starlette:
    """Create the reverse proxy Starlette app.

    Either ``backend_url`` (single backend) or ``backends`` (name→url dict)
    must be provided.
    """
    if middleware is None:
        _fpe = fpe_key or os.environ.get(
            "FPE_KEY", "EF4359D8D580AA4F7F036D6F04FC6A94",
        )
        _policy = policy_path or _resolve_policy_path()
        _mapping = mapping_path or str(default_mapping_path())
        middleware = _build_middleware(_policy, _mapping, _fpe)

    routes: list[Route | Mount] = []

    if backend_url:
        # Single backend — proxy everything at /
        handler = _create_proxy_route(backend_url, middleware)
        routes.append(Route("/{path:path}", handler, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]))
    elif backends:
        # Multiple backends — each mounted under /<name>/
        for name, url in backends.items():
            prefix = f"/{name}"
            handler = _create_proxy_route(url, middleware, prefix=prefix)
            routes.append(Mount(prefix, routes=[
                Route("/{path:path}", handler, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]),
                Route("/", handler, methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]),
            ]))
    else:
        raise ValueError("Provide either backend_url or backends")

    return Starlette(routes=routes)


def _resolve_policy_path() -> str:
    env = os.environ.get("CONFIG_PATH")
    if env:
        return env
    local = Path(__file__).parent / "policy.local.yaml"
    if local.exists():
        return str(local)
    data = default_policy_path()
    if data.exists():
        return str(data)
    return str(Path(__file__).parent / "default_policy.yaml")


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="MCP PII-masking HTTP reverse proxy")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "9100")))
    parser.add_argument("--host", default=os.environ.get("HOST", "127.0.0.1"))
    parser.add_argument("--backend-url", default=os.environ.get("BACKEND_URL"))
    parser.add_argument("--servers", default=os.environ.get("SERVERS_PATH", "servers.yaml"),
                        help="Path to servers.yaml for multi-backend mode")
    args = parser.parse_args()

    if args.backend_url:
        app = create_app(backend_url=args.backend_url)
        print(f"PII reverse proxy listening on http://{args.host}:{args.port}")
        print(f"  Forwarding to {args.backend_url}")
    else:
        servers_path = args.servers
        if Path(servers_path).exists():
            from server_registry import ServerRegistry
            registry = ServerRegistry(path=servers_path)
            backends = {
                name: entry.target
                for name, entry in registry.enabled_servers().items()
            }
            if not backends:
                print("No enabled servers in servers.yaml", file=sys.stderr)
                sys.exit(1)
            app = create_app(backends=backends)
            print(f"PII reverse proxy listening on http://{args.host}:{args.port}")
            for name, url in backends.items():
                print(f"  /{name} → {url}")
        else:
            print(
                "Provide --backend-url or --servers path/to/servers.yaml",
                file=sys.stderr,
            )
            sys.exit(1)

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
