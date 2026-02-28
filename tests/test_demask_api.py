"""Tests for de-masking API endpoints and MappingStore.demask_text()."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient
from starlette.applications import Starlette

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit import AuditLog
from config import PolicyConfig, EntityPolicy
from dashboard import create_dashboard_routes
from mapping_store import MappingStore
from server_registry import ServerRegistry


@pytest.fixture
def mapping_store():
    """A MappingStore pre-loaded with known mappings."""
    store = MappingStore()
    store.store("PERSON", "John Smith", "Maria Rodriguez")
    store.store("US_SSN", "123-45-6789", "831-24-5067")
    store.store("LOCATION", "Portland", "Springfield")
    return store


@pytest.fixture
def app(tmp_path, mapping_store):
    config_path = tmp_path / "policy.yaml"
    config_path.write_text(
        "entities:\n  DEFAULT:\n    operator: replace\n    new_value: '<REDACTED>'\n"
    )

    registry = ServerRegistry(path=tmp_path / "servers.yaml")
    policy = PolicyConfig(
        entities={"DEFAULT": EntityPolicy(operator="replace", new_value="<REDACTED>")},
    )
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


# ── MappingStore.demask_text() unit tests ──────────────────────────────


class TestDemaskText:
    """Direct tests for MappingStore.demask_text()."""

    def test_replaces_known_surrogates(self, mapping_store):
        text = "Found Maria Rodriguez, SSN 831-24-5067"
        demasked, replacements = mapping_store.demask_text(text)

        assert demasked == "Found John Smith, SSN 123-45-6789"
        assert len(replacements) == 2

        surrogates_replaced = {r["surrogate"] for r in replacements}
        assert "Maria Rodriguez" in surrogates_replaced
        assert "831-24-5067" in surrogates_replaced

    def test_no_surrogates_passthrough(self, mapping_store):
        text = "Nothing to see here"
        demasked, replacements = mapping_store.demask_text(text)

        assert demasked == text
        assert replacements == []

    def test_empty_store(self):
        store = MappingStore()
        text = "Maria Rodriguez"
        demasked, replacements = store.demask_text(text)

        assert demasked == text
        assert replacements == []

    def test_replacement_includes_entity_type(self, mapping_store):
        text = "Maria Rodriguez lives in Springfield"
        demasked, replacements = mapping_store.demask_text(text)

        types = {r["entity_type"] for r in replacements}
        assert "PERSON" in types
        assert "LOCATION" in types

    def test_longest_first_replacement(self):
        """Longer surrogates should be replaced before shorter substrings."""
        store = MappingStore()
        store.store("PERSON", "Real Name", "Maria Rodriguez")
        store.store("PERSON", "Other", "Maria")

        text = "Contact Maria Rodriguez please"
        demasked, replacements = store.demask_text(text)

        assert demasked == "Contact Real Name please"
        assert len(replacements) == 1
        assert replacements[0]["surrogate"] == "Maria Rodriguez"


# ── POST /api/demask ───────────────────────────────────────────────────


class TestApiDemask:
    def test_demask_with_replacements(self, client):
        resp = client.post("/api/demask", json={
            "text": "Found Maria Rodriguez, SSN 831-24-5067 in Springfield"
        })
        assert resp.status_code == 200
        data = resp.json()

        assert data["original"] == "Found Maria Rodriguez, SSN 831-24-5067 in Springfield"
        assert data["demasked"] == "Found John Smith, SSN 123-45-6789 in Portland"
        assert len(data["replacements"]) == 3

    def test_demask_no_surrogates(self, client):
        resp = client.post("/api/demask", json={"text": "Hello world"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["original"] == "Hello world"
        assert data["demasked"] == "Hello world"
        assert data["replacements"] == []

    def test_demask_empty_text(self, client):
        resp = client.post("/api/demask", json={"text": ""})
        assert resp.status_code == 200
        data = resp.json()

        assert data["demasked"] == ""
        assert data["replacements"] == []


# ── POST /api/demask/batch ─────────────────────────────────────────────


class TestApiDemaskBatch:
    def test_batch_multiple_texts(self, client):
        resp = client.post("/api/demask/batch", json={
            "texts": [
                "msg 1 with Maria Rodriguez",
                "msg 2 with 831-24-5067",
            ]
        })
        assert resp.status_code == 200
        data = resp.json()
        results = data["results"]

        assert len(results) == 2

        assert results[0]["original"] == "msg 1 with Maria Rodriguez"
        assert results[0]["demasked"] == "msg 1 with John Smith"
        assert len(results[0]["replacements"]) == 1

        assert results[1]["original"] == "msg 2 with 831-24-5067"
        assert results[1]["demasked"] == "msg 2 with 123-45-6789"
        assert len(results[1]["replacements"]) == 1

    def test_batch_empty_list(self, client):
        resp = client.post("/api/demask/batch", json={"texts": []})
        assert resp.status_code == 200
        assert resp.json()["results"] == []


# ── GET /api/mappings/lookup ───────────────────────────────────────────


class TestApiMappingsLookup:
    def test_lookup_found(self, client):
        resp = client.get("/api/mappings/lookup", params={"surrogate": "Maria Rodriguez"})
        assert resp.status_code == 200
        data = resp.json()

        assert data["surrogate"] == "Maria Rodriguez"
        assert data["entity_type"] == "PERSON"
        assert data["real_value"] == "John Smith"

    def test_lookup_not_found(self, client):
        resp = client.get("/api/mappings/lookup", params={"surrogate": "Unknown Person"})
        assert resp.status_code == 404
        assert "error" in resp.json()

    def test_lookup_missing_param(self, client):
        resp = client.get("/api/mappings/lookup")
        assert resp.status_code == 400
        assert "error" in resp.json()
