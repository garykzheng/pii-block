"""Tests for OAuth/auth support: ServerEntry auth fields, API endpoints, token safety."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml
from starlette.testclient import TestClient
from starlette.applications import Starlette

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import PolicyConfig, EntityPolicy
from dashboard import create_dashboard_routes
from mapping_store import MappingStore
from audit import AuditLog
from server_registry import ServerRegistry, ServerEntry


# ── ServerEntry auth fields ───────────────────────────────────────────────


class TestServerEntryAuth:
    """ServerEntry with auth and headers fields."""

    def test_default_auth_is_none(self):
        entry = ServerEntry(target="http://localhost:3000")
        assert entry.auth is None
        assert entry.headers is None

    def test_auth_oauth(self):
        entry = ServerEntry(target="http://localhost:3000", auth="oauth")
        assert entry.auth == "oauth"

    def test_auth_bearer_token(self):
        entry = ServerEntry(target="http://localhost:3000", auth="sk-secret-123")
        assert entry.auth == "sk-secret-123"

    def test_custom_headers(self):
        entry = ServerEntry(
            target="http://localhost:3000",
            headers={"X-API-Key": "abc123"},
        )
        assert entry.headers == {"X-API-Key": "abc123"}


# ── Registry set_auth / clear_auth ─────────────────────────────────────────


class TestRegistryAuth:
    """set_auth() and clear_auth() methods."""

    def test_set_auth_oauth(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        registry.add("slack", "https://mcp.slack.com/mcp")
        registry.set_auth("slack", auth="oauth")

        assert registry.get("slack").auth == "oauth"

    def test_set_auth_bearer(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        registry.add("test", "http://localhost:3000")
        registry.set_auth("test", auth="my-token-123")

        assert registry.get("test").auth == "my-token-123"

    def test_set_auth_headers(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        registry.add("test", "http://localhost:3000")
        registry.set_auth("test", headers={"X-Key": "val"})

        assert registry.get("test").headers == {"X-Key": "val"}

    def test_set_auth_both(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        registry.add("test", "http://localhost:3000")
        registry.set_auth("test", auth="oauth", headers={"X-Key": "val"})

        entry = registry.get("test")
        assert entry.auth == "oauth"
        assert entry.headers == {"X-Key": "val"}

    def test_clear_auth(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        registry.add("test", "http://localhost:3000")
        registry.set_auth("test", auth="oauth", headers={"X-Key": "val"})
        registry.clear_auth("test")

        entry = registry.get("test")
        assert entry.auth is None
        assert entry.headers is None

    def test_set_auth_nonexistent_raises(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        with pytest.raises(KeyError, match="not found"):
            registry.set_auth("nope", auth="oauth")

    def test_clear_auth_nonexistent_raises(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        with pytest.raises(KeyError, match="not found"):
            registry.clear_auth("nope")


# ── YAML persistence with auth fields ──────────────────────────────────────


class TestAuthPersistence:
    """Auth fields survive save/load cycle."""

    def test_oauth_persists(self, tmp_path):
        path = tmp_path / "servers.yaml"
        r1 = ServerRegistry(path=path)
        r1.add("slack", "https://mcp.slack.com/mcp")
        r1.set_auth("slack", auth="oauth")

        r2 = ServerRegistry(path=path)
        assert r2.get("slack").auth == "oauth"

    def test_bearer_persists(self, tmp_path):
        path = tmp_path / "servers.yaml"
        r1 = ServerRegistry(path=path)
        r1.add("test", "http://localhost:3000")
        r1.set_auth("test", auth="xoxb-secret-token")

        r2 = ServerRegistry(path=path)
        assert r2.get("test").auth == "xoxb-secret-token"

    def test_headers_persist(self, tmp_path):
        path = tmp_path / "servers.yaml"
        r1 = ServerRegistry(path=path)
        r1.add("test", "http://localhost:3000")
        r1.set_auth("test", headers={"Authorization": "Basic abc"})

        r2 = ServerRegistry(path=path)
        assert r2.get("test").headers == {"Authorization": "Basic abc"}

    def test_no_auth_omitted_from_yaml(self, tmp_path):
        path = tmp_path / "servers.yaml"
        r = ServerRegistry(path=path)
        r.add("test", "http://localhost:3000")

        data = yaml.safe_load(path.read_text())
        server_data = data["servers"]["test"]
        assert "auth" not in server_data
        assert "headers" not in server_data

    def test_cleared_auth_omitted_from_yaml(self, tmp_path):
        path = tmp_path / "servers.yaml"
        r = ServerRegistry(path=path)
        r.add("test", "http://localhost:3000")
        r.set_auth("test", auth="oauth")
        r.clear_auth("test")

        data = yaml.safe_load(path.read_text())
        server_data = data["servers"]["test"]
        assert "auth" not in server_data
        assert "headers" not in server_data


# ── Dashboard API endpoints ────────────────────────────────────────────────


@pytest.fixture
def auth_app(tmp_path):
    """Create a test Starlette app with auth-enabled dashboard routes."""
    config_path = tmp_path / "policy.yaml"
    config_path.write_text(
        "entities:\n  DEFAULT:\n    operator: replace\n    new_value: '<REDACTED>'\n"
    )

    registry = ServerRegistry(path=tmp_path / "servers.yaml")
    policy = PolicyConfig(
        entities={"DEFAULT": EntityPolicy(operator="replace", new_value="<REDACTED>")},
    )
    mapping_store = MappingStore()
    audit_log = AuditLog()

    rebuild_calls = []

    def mock_rebuild():
        rebuild_calls.append(1)

    routes = create_dashboard_routes(
        registry=registry,
        policy=policy,
        mapping_store=mapping_store,
        audit_log=audit_log,
        config_path=str(config_path),
        rebuild_proxy=mock_rebuild,
    )

    app = Starlette(routes=routes)
    app.state.registry = registry
    app.state.rebuild_calls = rebuild_calls
    return app


@pytest.fixture
def auth_client(auth_app):
    return TestClient(auth_app)


class TestAuthAPIEndpoints:
    """JSON API endpoints for auth management."""

    def _add_server(self, client):
        client.post("/servers", data={"name": "test-srv", "target": "http://localhost:3000"})

    def test_set_auth_oauth(self, auth_client, auth_app):
        self._add_server(auth_client)
        resp = auth_client.post(
            "/api/servers/test-srv/auth",
            json={"auth": "oauth"},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        assert auth_app.state.registry.get("test-srv").auth == "oauth"

    def test_set_auth_bearer(self, auth_client, auth_app):
        self._add_server(auth_client)
        resp = auth_client.post(
            "/api/servers/test-srv/auth",
            json={"auth": "my-secret-token"},
        )
        assert resp.status_code == 200
        assert auth_app.state.registry.get("test-srv").auth == "my-secret-token"

    def test_set_auth_headers(self, auth_client, auth_app):
        self._add_server(auth_client)
        resp = auth_client.post(
            "/api/servers/test-srv/auth",
            json={"headers": {"X-API-Key": "abc"}},
        )
        assert resp.status_code == 200
        assert auth_app.state.registry.get("test-srv").headers == {"X-API-Key": "abc"}

    def test_set_auth_missing_body(self, auth_client):
        self._add_server(auth_client)
        resp = auth_client.post(
            "/api/servers/test-srv/auth",
            json={},
        )
        assert resp.status_code == 400

    def test_set_auth_nonexistent_server(self, auth_client):
        resp = auth_client.post(
            "/api/servers/nope/auth",
            json={"auth": "oauth"},
        )
        assert resp.status_code == 404

    def test_clear_auth(self, auth_client, auth_app):
        self._add_server(auth_client)
        auth_client.post("/api/servers/test-srv/auth", json={"auth": "oauth"})
        resp = auth_client.delete("/api/servers/test-srv/auth")
        assert resp.status_code == 200
        assert auth_app.state.registry.get("test-srv").auth is None

    def test_clear_auth_nonexistent(self, auth_client):
        resp = auth_client.delete("/api/servers/nope/auth")
        assert resp.status_code == 404

    def test_auth_status_none(self, auth_client):
        self._add_server(auth_client)
        resp = auth_client.get("/api/servers/test-srv/auth/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_auth"] is False
        assert data["auth_type"] is None

    def test_auth_status_oauth(self, auth_client):
        self._add_server(auth_client)
        auth_client.post("/api/servers/test-srv/auth", json={"auth": "oauth"})
        resp = auth_client.get("/api/servers/test-srv/auth/status")
        data = resp.json()
        assert data["has_auth"] is True
        assert data["auth_type"] == "oauth"

    def test_auth_status_bearer(self, auth_client):
        self._add_server(auth_client)
        auth_client.post("/api/servers/test-srv/auth", json={"auth": "secret-token"})
        resp = auth_client.get("/api/servers/test-srv/auth/status")
        data = resp.json()
        assert data["has_auth"] is True
        assert data["auth_type"] == "bearer"

    def test_auth_status_nonexistent(self, auth_client):
        resp = auth_client.get("/api/servers/nope/auth/status")
        assert resp.status_code == 404

    def test_rebuild_called_on_set(self, auth_client, auth_app):
        self._add_server(auth_client)
        auth_app.state.rebuild_calls.clear()
        auth_client.post("/api/servers/test-srv/auth", json={"auth": "oauth"})
        assert len(auth_app.state.rebuild_calls) == 1

    def test_rebuild_called_on_clear(self, auth_client, auth_app):
        self._add_server(auth_client)
        auth_client.post("/api/servers/test-srv/auth", json={"auth": "oauth"})
        auth_app.state.rebuild_calls.clear()
        auth_client.delete("/api/servers/test-srv/auth")
        assert len(auth_app.state.rebuild_calls) == 1


class TestTokenNotExposed:
    """Tokens must never appear in GET /api/servers responses."""

    def test_bearer_token_hidden(self, auth_client):
        self._add_server(auth_client)
        auth_client.post("/api/servers/test-srv/auth", json={"auth": "super-secret-token-xyz"})

        resp = auth_client.get("/api/servers")
        data = resp.json()
        server = data["test-srv"]

        # Should have auth_type but NOT the actual token
        assert server["auth_type"] == "bearer"
        assert server["has_auth"] is True
        assert "super-secret-token-xyz" not in str(data)

    def test_oauth_shows_type(self, auth_client):
        self._add_server(auth_client)
        auth_client.post("/api/servers/test-srv/auth", json={"auth": "oauth"})

        resp = auth_client.get("/api/servers")
        data = resp.json()
        server = data["test-srv"]
        assert server["auth_type"] == "oauth"
        assert server["has_auth"] is True

    def test_no_auth_shown(self, auth_client):
        self._add_server(auth_client)
        resp = auth_client.get("/api/servers")
        data = resp.json()
        server = data["test-srv"]
        assert server["auth_type"] is None
        assert server["has_auth"] is False

    def _add_server(self, client):
        client.post("/servers", data={"name": "test-srv", "target": "http://localhost:3000"})


class TestServersPageAuth:
    """Dashboard servers page shows auth controls."""

    def test_auth_column_in_table(self, auth_client):
        auth_client.post("/servers", data={"name": "srv", "target": "http://a"})
        resp = auth_client.get("/servers")
        assert "Auth</th>" in resp.text

    def test_authenticate_button(self, auth_client):
        auth_client.post("/servers", data={"name": "srv", "target": "http://a"})
        resp = auth_client.get("/servers")
        assert "Authenticate" in resp.text

    def test_clear_auth_button(self, auth_client):
        auth_client.post("/servers", data={"name": "srv", "target": "http://a"})
        resp = auth_client.get("/servers")
        assert "Clear Auth" in resp.text

    def test_auth_badge_none(self, auth_client):
        auth_client.post("/servers", data={"name": "srv", "target": "http://a"})
        resp = auth_client.get("/servers")
        assert "badge-off\">None</span>" in resp.text

    def test_add_server_with_oauth(self, auth_client, auth_app):
        auth_client.post(
            "/servers",
            data={"name": "oauth-srv", "target": "https://mcp.example.com", "auth": "oauth"},
        )
        entry = auth_app.state.registry.get("oauth-srv")
        assert entry is not None
        assert entry.auth == "oauth"

    def test_form_set_token(self, auth_client, auth_app):
        auth_client.post("/servers", data={"name": "tok-srv", "target": "http://a"})
        auth_client.post(
            "/servers/auth/token",
            data={"name": "tok-srv", "token": "my-bearer-token"},
        )
        assert auth_app.state.registry.get("tok-srv").auth == "my-bearer-token"

    def test_form_oauth_button(self, auth_client, auth_app):
        auth_client.post("/servers", data={"name": "srv", "target": "http://a"})
        auth_client.post("/servers/srv/auth/oauth")
        assert auth_app.state.registry.get("srv").auth == "oauth"

    def test_form_clear_auth(self, auth_client, auth_app):
        auth_client.post("/servers", data={"name": "srv", "target": "http://a"})
        auth_client.post("/servers/srv/auth/oauth")
        auth_client.post("/servers/srv/auth/clear")
        assert auth_app.state.registry.get("srv").auth is None
