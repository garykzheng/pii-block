"""Dashboard routes for the MCP Privacy Proxy management interface.

Provides HTML pages and JSON API endpoints for monitoring and managing
the proxy. All routes are pure Starlette — no JS frameworks required.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

if TYPE_CHECKING:
    from audit import AuditLog
    from config import PolicyConfig
    from mapping_store import MappingStore
    from server_registry import ServerRegistry

# ── HTML helpers ──────────────────────────────────────────────────────────

_CSS = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f5f5f5; color: #333; line-height: 1.6; }
  .container { max-width: 960px; margin: 0 auto; padding: 20px; }
  nav { background: #1a1a2e; padding: 12px 20px; }
  nav a { color: #e0e0e0; text-decoration: none; margin-right: 20px; font-weight: 500; }
  nav a:hover { color: #fff; }
  nav .brand { font-weight: 700; color: #4fc3f7; margin-right: 30px; }
  h1 { margin: 20px 0 10px; }
  h2 { margin: 15px 0 8px; color: #555; }
  .card { background: #fff; border-radius: 8px; padding: 20px; margin: 15px 0;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
  .stats { display: flex; gap: 15px; flex-wrap: wrap; }
  .stat { background: #fff; border-radius: 8px; padding: 15px 20px; flex: 1; min-width: 140px;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }
  .stat .num { font-size: 2em; font-weight: 700; color: #1a1a2e; }
  .stat .label { font-size: 0.85em; color: #888; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; }
  th, td { padding: 10px 12px; text-align: left; border-bottom: 1px solid #eee; }
  th { background: #fafafa; font-weight: 600; color: #555; font-size: 0.85em; text-transform: uppercase; }
  tr:hover { background: #f9f9f9; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }
  .badge-on { background: #c8e6c9; color: #2e7d32; }
  .badge-off { background: #ffcdd2; color: #c62828; }
  .badge-type { background: #e3f2fd; color: #1565c0; }
  button, .btn { background: #1a1a2e; color: #fff; border: none; padding: 8px 16px; border-radius: 5px;
                 cursor: pointer; font-size: 0.9em; text-decoration: none; display: inline-block; }
  button:hover, .btn:hover { background: #16213e; }
  .btn-danger { background: #c62828; }
  .btn-danger:hover { background: #b71c1c; }
  .btn-sm { padding: 4px 10px; font-size: 0.8em; }
  input, textarea { padding: 8px 12px; border: 1px solid #ddd; border-radius: 5px; font-size: 0.95em; width: 100%; }
  textarea { font-family: "SF Mono", "Fira Code", monospace; font-size: 0.85em; }
  form { margin: 10px 0; }
  .form-row { display: flex; gap: 10px; margin: 10px 0; align-items: end; }
  .form-row label { font-size: 0.85em; color: #555; display: block; margin-bottom: 4px; }
  .form-row .field { flex: 1; }
  .banner { background: #fff3e0; border-left: 4px solid #ff9800; padding: 12px 16px; margin: 15px 0;
            border-radius: 0 5px 5px 0; }
  .mono { font-family: "SF Mono", "Fira Code", monospace; font-size: 0.85em; }
  .empty { text-align: center; padding: 40px; color: #999; }
</style>
"""


def _layout(title: str, content: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — MCP Privacy Proxy</title>{_CSS}</head>
<body>
<nav>
  <a href="/" class="brand">MCP Privacy Proxy</a>
  <a href="/">Dashboard</a>
  <a href="/servers">Servers</a>
  <a href="/audit">Audit Log</a>
  <a href="/policy">Policy</a>
</nav>
<div class="container">{content}</div>
</body></html>"""


# ── Route handlers ────────────────────────────────────────────────────────

def create_dashboard_routes(
    registry: ServerRegistry,
    policy: PolicyConfig,
    mapping_store: MappingStore,
    audit_log: AuditLog,
    config_path: str,
    middleware: object | None = None,
) -> list[Route]:
    """Create all dashboard routes with shared state.

    The middleware parameter, if provided, should be the PrivacyMiddleware instance
    so we can call reload_policy() on hot-reload.
    """

    # ── Dashboard home ────────────────────────────────────────────────

    async def home(request: Request) -> HTMLResponse:
        stats = audit_log.stats()
        servers = registry.all_servers()
        enabled = sum(1 for s in servers.values() if s.enabled)
        mappings = mapping_store.dump()
        mapping_count = sum(len(v) for v in mappings.values())

        content = f"""
        <h1>Dashboard</h1>
        <div class="stats">
          <div class="stat"><div class="num">{len(servers)}</div><div class="label">Servers ({enabled} enabled)</div></div>
          <div class="stat"><div class="num">{mapping_count}</div><div class="label">PII Mappings</div></div>
          <div class="stat"><div class="num">{stats['total_events']}</div><div class="label">Audit Events</div></div>
          <div class="stat"><div class="num">{stats['total_masked']}</div><div class="label">Items Masked</div></div>
        </div>

        <div class="card">
          <h2>Entity Types Detected</h2>
          {''.join(f'<span class="badge badge-type" style="margin:3px">{et}: {c}</span>' for et, c in stats["entity_type_counts"].items()) or '<p class="empty">No PII detected yet</p>'}
        </div>

        <div class="card">
          <h2>Recent Activity</h2>
          {'<table><tr><th>Time</th><th>Tool</th><th>Direction</th><th>Entities</th><th>Count</th></tr>' +
           ''.join(f'<tr><td class="mono">{e.timestamp[11:19]}</td><td>{e.tool_name}</td>'
                   f'<td>{e.direction}</td><td>{", ".join(e.entity_types)}</td>'
                   f'<td>{e.masked_count or e.demapped_count}</td></tr>'
                   for e in audit_log.recent(10)) +
           '</table>' if len(audit_log) > 0 else '<p class="empty">No activity yet</p>'}
        </div>
        """
        return HTMLResponse(_layout("Dashboard", content))

    # ── Servers ───────────────────────────────────────────────────────

    async def servers_page(request: Request) -> HTMLResponse:
        all_servers = registry.all_servers()

        rows = ""
        for name, entry in all_servers.items():
            badge = '<span class="badge badge-on">ON</span>' if entry.enabled else '<span class="badge badge-off">OFF</span>'
            toggle_label = "Disable" if entry.enabled else "Enable"
            rows += f"""<tr>
              <td><strong>{name}</strong></td>
              <td class="mono">{entry.target}</td>
              <td>{badge}</td>
              <td class="mono">{entry.added_at[:10]}</td>
              <td>
                <form method="post" action="/servers/{name}/toggle" style="display:inline">
                  <button class="btn-sm">{toggle_label}</button>
                </form>
                <form method="post" action="/servers/{name}/delete" style="display:inline; margin-left:5px">
                  <button class="btn-sm btn-danger">Remove</button>
                </form>
              </td>
            </tr>"""

        content = f"""
        <h1>Servers</h1>
        <div class="banner">Changes to servers require a proxy restart to take effect.</div>

        <div class="card">
          <h2>Add Server</h2>
          <form method="post" action="/servers">
            <div class="form-row">
              <div class="field"><label>Name</label><input name="name" placeholder="my-server" required></div>
              <div class="field"><label>Target (URL or command)</label><input name="target" placeholder="http://localhost:3001/mcp" required></div>
              <div class="field" style="flex:0"><label>&nbsp;</label><button type="submit">Add</button></div>
            </div>
          </form>
        </div>

        <div class="card">
          <h2>Registered Servers</h2>
          {'<table><tr><th>Name</th><th>Target</th><th>Status</th><th>Added</th><th>Actions</th></tr>' +
           rows + '</table>' if rows else '<p class="empty">No servers registered</p>'}
        </div>
        """
        return HTMLResponse(_layout("Servers", content))

    async def servers_add(request: Request) -> RedirectResponse:
        form = await request.form()
        name = str(form.get("name", "")).strip()
        target = str(form.get("target", "")).strip()
        if name and target:
            try:
                registry.add(name, target)
            except ValueError:
                pass  # Already exists
        return RedirectResponse("/servers", status_code=303)

    async def servers_toggle(request: Request) -> RedirectResponse:
        name = request.path_params["name"]
        entry = registry.get(name)
        if entry:
            if entry.enabled:
                registry.disable(name)
            else:
                registry.enable(name)
        return RedirectResponse("/servers", status_code=303)

    async def servers_delete(request: Request) -> RedirectResponse:
        name = request.path_params["name"]
        try:
            registry.remove(name)
        except KeyError:
            pass
        return RedirectResponse("/servers", status_code=303)

    # ── Audit log ─────────────────────────────────────────────────────

    async def audit_page(request: Request) -> HTMLResponse:
        events = audit_log.recent(100)

        rows = ""
        for e in events:
            rows += f"""<tr>
              <td class="mono">{e.timestamp[11:19]}</td>
              <td>{e.server or '-'}</td>
              <td>{e.tool_name}</td>
              <td>{e.direction}</td>
              <td>{''.join(f'<span class="badge badge-type" style="margin:2px">{et}</span>' for et in e.entity_types)}</td>
              <td>{e.masked_count}</td>
              <td>{e.demapped_count}</td>
            </tr>"""

        content = f"""
        <h1>Audit Log</h1>
        <div class="card">
          <p>Showing up to 100 most recent events (session-scoped, not persisted).</p>
          {'<table><tr><th>Time</th><th>Server</th><th>Tool</th><th>Dir</th><th>Entity Types</th><th>Masked</th><th>Demapped</th></tr>' +
           rows + '</table>' if rows else '<p class="empty">No audit events yet</p>'}
        </div>
        """
        return HTMLResponse(_layout("Audit Log", content))

    # ── Policy editor ─────────────────────────────────────────────────

    async def policy_page(request: Request) -> HTMLResponse:
        from pathlib import Path as P
        import yaml

        policy_text = ""
        p = P(config_path)
        if p.exists():
            policy_text = p.read_text()

        msg = ""
        if request.query_params.get("saved") == "1":
            msg = '<div class="banner" style="border-color:#4caf50;background:#e8f5e9">Policy saved and reloaded.</div>'
        elif request.query_params.get("error"):
            msg = f'<div class="banner" style="border-color:#c62828;background:#ffebee">Error: {request.query_params["error"]}</div>'

        content = f"""
        <h1>Policy Editor</h1>
        {msg}
        <div class="card">
          <form method="post" action="/policy">
            <textarea name="policy" rows="25" style="width:100%">{policy_text}</textarea>
            <div style="margin-top:10px"><button type="submit">Save &amp; Reload</button></div>
          </form>
        </div>
        """
        return HTMLResponse(_layout("Policy", content))

    async def policy_save(request: Request) -> RedirectResponse:
        from pathlib import Path as P
        import yaml
        from config import load_policy as _load_policy

        form = await request.form()
        raw = str(form.get("policy", ""))

        # Validate YAML
        try:
            yaml.safe_load(raw)
        except yaml.YAMLError as e:
            return RedirectResponse(f"/policy?error=Invalid+YAML:+{e}", status_code=303)

        # Write and reload
        p = P(config_path)
        p.write_text(raw)

        try:
            new_policy = _load_policy(config_path)
        except Exception as e:
            return RedirectResponse(f"/policy?error=Policy+load+failed:+{e}", status_code=303)

        # Hot-reload into running middleware
        if middleware and hasattr(middleware, "reload_policy"):
            middleware.reload_policy(new_policy)  # type: ignore[union-attr]

        # Update the shared policy reference
        nonlocal policy
        policy = new_policy

        return RedirectResponse("/policy?saved=1", status_code=303)

    # ── JSON API ──────────────────────────────────────────────────────

    async def api_stats(request: Request) -> JSONResponse:
        return JSONResponse(audit_log.stats())

    async def api_servers(request: Request) -> JSONResponse:
        return JSONResponse({
            name: {"target": e.target, "enabled": e.enabled, "added_at": e.added_at}
            for name, e in registry.all_servers().items()
        })

    async def api_audit(request: Request) -> JSONResponse:
        return JSONResponse(audit_log.to_json())

    async def api_mappings(request: Request) -> JSONResponse:
        return JSONResponse(mapping_store.dump())

    # ── De-masking API ─────────────────────────────────────────────────

    async def api_demask(request: Request) -> JSONResponse:
        body = await request.json()
        text = body.get("text", "")
        demasked, replacements = mapping_store.demask_text(text)
        return JSONResponse({
            "original": body.get("text", ""),
            "demasked": demasked,
            "replacements": replacements,
        })

    async def api_demask_batch(request: Request) -> JSONResponse:
        body = await request.json()
        texts = body.get("texts", [])
        results = []
        for t in texts:
            demasked, replacements = mapping_store.demask_text(t)
            results.append({
                "original": t,
                "demasked": demasked,
                "replacements": replacements,
            })
        return JSONResponse({"results": results})

    async def api_mappings_lookup(request: Request) -> JSONResponse:
        surrogate = request.query_params.get("surrogate", "")
        if not surrogate:
            return JSONResponse({"error": "missing 'surrogate' query parameter"}, status_code=400)
        result = mapping_store.has_surrogate_anywhere(surrogate)
        if result is None:
            return JSONResponse({"error": "surrogate not found"}, status_code=404)
        entity_type, real_value = result
        return JSONResponse({
            "surrogate": surrogate,
            "entity_type": entity_type,
            "real_value": real_value,
        })

    # ── Compose routes ────────────────────────────────────────────────

    return [
        Route("/", home),
        Route("/servers", servers_page, methods=["GET"]),
        Route("/servers", servers_add, methods=["POST"]),
        Route("/servers/{name}/toggle", servers_toggle, methods=["POST"]),
        Route("/servers/{name}/delete", servers_delete, methods=["POST"]),
        Route("/audit", audit_page),
        Route("/policy", policy_page, methods=["GET"]),
        Route("/policy", policy_save, methods=["POST"]),
        Route("/api/stats", api_stats),
        Route("/api/servers", api_servers),
        Route("/api/audit", api_audit),
        Route("/api/mappings", api_mappings),
        Route("/api/demask", api_demask, methods=["POST"]),
        Route("/api/demask/batch", api_demask_batch, methods=["POST"]),
        Route("/api/mappings/lookup", api_mappings_lookup),
    ]
