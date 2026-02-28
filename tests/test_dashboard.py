"""Tests for dashboard routes: HTTP responses and basic functionality."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient
from starlette.applications import Starlette

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit import AuditLog, AuditEvent
from config import PolicyConfig, EntityPolicy
from dashboard import create_dashboard_routes
from mapping_store import MappingStore
from server_registry import ServerRegistry


@pytest.fixture
def app(tmp_path):
    """Create a test Starlette app with dashboard routes."""
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

    routes = create_dashboard_routes(
        registry=registry,
        policy=policy,
        mapping_store=mapping_store,
        audit_log=audit_log,
        config_path=str(config_path),
    )

    return Starlette(routes=routes)


@pytest.fixture
def client(app):
    return TestClient(app)


class TestDashboardPages:
    """All HTML pages should return 200."""

    def test_home(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Dashboard" in resp.text

    def test_servers_page(self, client):
        resp = client.get("/servers")
        assert resp.status_code == 200
        assert "Servers" in resp.text

    def test_audit_page(self, client):
        resp = client.get("/audit")
        assert resp.status_code == 200
        assert "Audit Log" in resp.text

    def test_policy_page(self, client):
        resp = client.get("/policy")
        assert resp.status_code == 200
        assert "Policy" in resp.text


class TestServerCRUD:
    """Server management via POST forms."""

    def test_add_server(self, client):
        resp = client.post(
            "/servers",
            data={"name": "test-server", "target": "http://localhost:3000"},
            follow_redirects=False,
        )
        assert resp.status_code == 303

        # Verify it appears on the page
        page = client.get("/servers")
        assert "test-server" in page.text

    def test_toggle_server(self, client):
        # Add a server first
        client.post("/servers", data={"name": "srv", "target": "http://a"}, follow_redirects=False)

        # Toggle (disable)
        resp = client.post("/servers/srv/toggle", follow_redirects=False)
        assert resp.status_code == 303

    def test_delete_server(self, client):
        client.post("/servers", data={"name": "srv", "target": "http://a"}, follow_redirects=False)

        resp = client.post("/servers/srv/delete", follow_redirects=False)
        assert resp.status_code == 303


class TestAPIs:
    """JSON API endpoints."""

    def test_api_stats(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_events" in data

    def test_api_servers(self, client):
        resp = client.get("/api/servers")
        assert resp.status_code == 200
        assert isinstance(resp.json(), dict)

    def test_api_audit(self, client):
        resp = client.get("/api/audit")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_api_mappings(self, client):
        resp = client.get("/api/mappings")
        assert resp.status_code == 200
        assert isinstance(resp.json(), dict)


class TestPolicyEditor:
    """Policy save/reload."""

    def test_save_valid_policy(self, client):
        policy_yaml = "entities:\n  PERSON:\n    operator: replace\n    new_value: '<NAME>'\n"
        resp = client.post(
            "/policy",
            data={"policy": policy_yaml},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "saved=1" in resp.headers.get("location", "")

    def test_save_invalid_yaml(self, client):
        resp = client.post(
            "/policy",
            data={"policy": "{{invalid yaml::"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        location = resp.headers.get("location", "")
        assert "error" in location
