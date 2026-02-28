"""Tests for MappingStore: CRUD, persistence, partial reconciliation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mapping_store import MappingStore, _partial_to_regex


class TestBasicCRUD:
    """Store and retrieve mappings."""

    def test_store_and_retrieve(self):
        store = MappingStore()
        store.store("US_SSN", "123-45-6789", "987-65-4321")

        assert store.get_surrogate("US_SSN", "123-45-6789") == "987-65-4321"
        assert store.get_real_value("US_SSN", "987-65-4321") == "123-45-6789"

    def test_missing_returns_none(self):
        store = MappingStore()

        assert store.get_surrogate("US_SSN", "000-00-0000") is None
        assert store.get_real_value("US_SSN", "000-00-0000") is None

    def test_multiple_entity_types(self):
        store = MappingStore()
        store.store("US_SSN", "123-45-6789", "987-65-4321")
        store.store("PERSON", "John Smith", "Jane Doe")

        assert store.get_surrogate("US_SSN", "123-45-6789") == "987-65-4321"
        assert store.get_surrogate("PERSON", "John Smith") == "Jane Doe"
        assert store.get_surrogate("US_SSN", "John Smith") is None

    def test_overwrite_mapping(self):
        store = MappingStore()
        store.store("US_SSN", "123-45-6789", "old-value")
        store.store("US_SSN", "123-45-6789", "new-value")

        assert store.get_surrogate("US_SSN", "123-45-6789") == "new-value"

    def test_has_surrogate_anywhere(self):
        store = MappingStore()
        store.store("PERSON", "John Smith", "FakeName")

        result = store.has_surrogate_anywhere("FakeName")
        assert result == ("PERSON", "John Smith")

        assert store.has_surrogate_anywhere("nonexistent") is None


class TestAllSurrogates:
    """Test the all_surrogates() method."""

    def test_returns_all_surrogates(self):
        store = MappingStore()
        store.store("US_SSN", "111-11-1111", "AAA")
        store.store("PERSON", "Bob", "BBB")
        store.store("EMAIL_ADDRESS", "a@b.com", "CCC")

        surrogates = store.all_surrogates()
        assert surrogates == {"AAA", "BBB", "CCC"}

    def test_empty_store(self):
        store = MappingStore()
        assert store.all_surrogates() == set()


class TestPersistence:
    """JSON file persistence."""

    def test_save_and_load(self, tmp_path):
        path = tmp_path / "mappings.json"

        # Save
        store1 = MappingStore(path=path)
        store1.store("US_SSN", "123-45-6789", "987-65-4321")
        store1.store("PERSON", "John Smith", "Jane Doe")
        store1._save_sync()

        # Load in a new instance
        store2 = MappingStore(path=path)

        assert store2.get_surrogate("US_SSN", "123-45-6789") == "987-65-4321"
        assert store2.get_real_value("US_SSN", "987-65-4321") == "123-45-6789"
        assert store2.get_surrogate("PERSON", "John Smith") == "Jane Doe"

    def test_persists_valid_json(self, tmp_path):
        path = tmp_path / "mappings.json"
        store = MappingStore(path=path)
        store.store("US_SSN", "123-45-6789", "987-65-4321")
        store._save_sync()

        data = json.loads(path.read_text())
        assert "forward" in data
        assert "US_SSN" in data["forward"]

    def test_load_nonexistent_file(self, tmp_path):
        path = tmp_path / "nonexistent.json"
        store = MappingStore(path=path)

        # Should not raise, just start empty
        assert store.get_surrogate("US_SSN", "anything") is None

    @pytest.mark.asyncio
    async def test_async_save_load(self, tmp_path):
        path = tmp_path / "async_mappings.json"

        store1 = MappingStore(path=path)
        store1.store("PERSON", "Alice", "Bob")
        await store1.save()

        store2 = MappingStore()
        store2._path = path
        await store2.load()

        assert store2.get_surrogate("PERSON", "Alice") == "Bob"


class TestPartialReconciliation:
    """Partially masked values should match against full values."""

    def test_ssn_partial_match(self):
        store = MappingStore()
        store.store("US_SSN", "123-45-6789", "987-65-4321")

        # Partial mask: last 4 digits visible
        result = store.reconcile_partial("US_SSN", "***-**-6789")
        assert result == "987-65-4321"

    def test_ssn_partial_no_match(self):
        store = MappingStore()
        store.store("US_SSN", "123-45-6789", "987-65-4321")

        result = store.reconcile_partial("US_SSN", "***-**-0000")
        assert result is None

    def test_ssn_partial_ambiguous(self):
        store = MappingStore()
        store.store("US_SSN", "123-45-6789", "aaa-bb-cccc")
        store.store("US_SSN", "987-65-6789", "xxx-yy-zzzz")

        # Two SSNs end in 6789 — ambiguous, should return None
        result = store.reconcile_partial("US_SSN", "***-**-6789")
        assert result is None

    def test_cc_partial_match(self):
        store = MappingStore()
        store.store("CREDIT_CARD", "4111-1111-1111-1111", "9999-8888-7777-6666")

        result = store.reconcile_partial("CREDIT_CARD", "XXXX-XXXX-XXXX-1111")
        assert result == "9999-8888-7777-6666"

    def test_no_mask_chars_returns_none(self):
        store = MappingStore()
        store.store("US_SSN", "123-45-6789", "987-65-4321")

        result = store.reconcile_partial("US_SSN", "123-45-6789")
        assert result is None  # No mask chars, nothing to reconcile


class TestPartialToRegex:
    """Unit tests for the _partial_to_regex helper."""

    def test_ssn_partial(self):
        pattern = _partial_to_regex("***-**-6789")
        assert pattern is not None
        import re
        assert re.fullmatch(pattern, "123-45-6789")
        assert not re.fullmatch(pattern, "123-45-0000")

    def test_no_mask_chars(self):
        assert _partial_to_regex("123-45-6789") is None

    def test_all_mask_chars(self):
        pattern = _partial_to_regex("*****")
        assert pattern is not None
        import re
        assert re.fullmatch(pattern, "abcde")
