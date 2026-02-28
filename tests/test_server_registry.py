"""Tests for ServerRegistry: CRUD, persistence, from_single compat."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from server_registry import ServerRegistry, ServerEntry


class TestBasicCRUD:
    """Add, remove, enable, disable servers."""

    def test_add_server(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        registry.add("test", "http://localhost:3000/mcp")

        assert len(registry) == 1
        entry = registry.get("test")
        assert entry is not None
        assert entry.target == "http://localhost:3000/mcp"
        assert entry.enabled is True

    def test_add_duplicate_raises(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        registry.add("test", "http://localhost:3000")

        with pytest.raises(ValueError, match="already exists"):
            registry.add("test", "http://localhost:3001")

    def test_remove_server(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        registry.add("test", "http://localhost:3000")
        registry.remove("test")

        assert len(registry) == 0
        assert registry.get("test") is None

    def test_remove_nonexistent_raises(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")

        with pytest.raises(KeyError, match="not found"):
            registry.remove("nonexistent")

    def test_enable_disable(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        registry.add("test", "http://localhost:3000")

        registry.disable("test")
        assert registry.get("test").enabled is False

        registry.enable("test")
        assert registry.get("test").enabled is True

    def test_enabled_servers_filter(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "servers.yaml")
        registry.add("on1", "http://a")
        registry.add("on2", "http://b")
        registry.add("off1", "http://c")
        registry.disable("off1")

        enabled = registry.enabled_servers()
        assert "on1" in enabled
        assert "on2" in enabled
        assert "off1" not in enabled


class TestPersistence:
    """YAML file persistence."""

    def test_save_and_load(self, tmp_path):
        path = tmp_path / "servers.yaml"

        r1 = ServerRegistry(path=path)
        r1.add("server1", "http://localhost:3000")
        r1.add("server2", "npx some-command")
        r1.disable("server2")

        r2 = ServerRegistry(path=path)
        assert len(r2) == 2
        assert r2.get("server1").enabled is True
        assert r2.get("server2").enabled is False
        assert r2.get("server2").target == "npx some-command"

    def test_persists_valid_yaml(self, tmp_path):
        path = tmp_path / "servers.yaml"
        r = ServerRegistry(path=path)
        r.add("test", "http://example.com")

        data = yaml.safe_load(path.read_text())
        assert "servers" in data
        assert "test" in data["servers"]
        assert data["servers"]["test"]["target"] == "http://example.com"

    def test_load_nonexistent(self, tmp_path):
        registry = ServerRegistry(path=tmp_path / "nope.yaml")
        assert len(registry) == 0


class TestFromSingle:
    """Backwards compatibility with single-server env vars."""

    def test_from_single_url(self):
        registry = ServerRegistry.from_single("http://localhost:3000/mcp")
        assert len(registry) == 1
        servers = registry.enabled_servers()
        assert "default" in servers
        assert servers["default"].target == "http://localhost:3000/mcp"

    def test_from_single_command(self):
        registry = ServerRegistry.from_single("npx some-server", name="myserver")
        assert registry.get("myserver").target == "npx some-server"
