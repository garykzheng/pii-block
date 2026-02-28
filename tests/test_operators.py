"""Tests for custom Presidio operators: FPE roundtrip, Faker determinism, format preservation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Allow imports from the project root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mapping_store import MappingStore
from operators import (
    FPEAnonymizer,
    FPEDeanonymizer,
    DeterministicFakerAnonymizer,
    MappingDeanonymizer,
)

# Test key and tweaks (for development use only)
TEST_KEY = "EF4359D8D580AA4F7F036D6F04FC6A94"
TEST_TWEAK_SSN = "CBD09280979564"
TEST_TWEAK_CC = "A1B2C3D4E5F6A7"


class TestFPERoundtrip:
    """FPE encrypt → decrypt should return the original value."""

    def setup_method(self):
        self.enc = FPEAnonymizer()
        self.dec = FPEDeanonymizer()

    def test_ssn_roundtrip(self):
        ssn = "123-45-6789"
        params = {"key": TEST_KEY, "tweak": TEST_TWEAK_SSN, "entity_type": "US_SSN"}

        encrypted = self.enc.operate(ssn, params)
        decrypted = self.dec.operate(encrypted, params)

        assert decrypted == ssn
        assert encrypted != ssn

    def test_credit_card_roundtrip(self):
        cc = "4111-1111-1111-1111"
        params = {"key": TEST_KEY, "tweak": TEST_TWEAK_CC, "entity_type": "CREDIT_CARD"}

        encrypted = self.enc.operate(cc, params)
        decrypted = self.dec.operate(encrypted, params)

        assert decrypted == cc
        assert encrypted != cc

    def test_phone_roundtrip(self):
        phone = "(555) 867-5309"
        params = {"key": TEST_KEY, "tweak": TEST_TWEAK_SSN, "entity_type": "PHONE_NUMBER"}

        encrypted = self.enc.operate(phone, params)
        decrypted = self.dec.operate(encrypted, params)

        assert decrypted == phone

    def test_bare_digits_roundtrip(self):
        digits = "9876543210"
        params = {"key": TEST_KEY, "tweak": TEST_TWEAK_SSN}

        encrypted = self.enc.operate(digits, params)
        decrypted = self.dec.operate(encrypted, params)

        assert decrypted == digits


class TestFPEFormatPreservation:
    """FPE output must preserve the format of the input."""

    def setup_method(self):
        self.enc = FPEAnonymizer()

    def test_ssn_format_preserved(self):
        ssn = "123-45-6789"
        params = {"key": TEST_KEY, "tweak": TEST_TWEAK_SSN}

        result = self.enc.operate(ssn, params)

        # Should still match SSN format: NNN-NN-NNNN
        import re
        assert re.fullmatch(r"\d{3}-\d{2}-\d{4}", result), f"Format broken: {result}"

    def test_credit_card_format_preserved(self):
        cc = "4111-1111-1111-1111"
        params = {"key": TEST_KEY, "tweak": TEST_TWEAK_CC}

        result = self.enc.operate(cc, params)

        import re
        assert re.fullmatch(r"\d{4}-\d{4}-\d{4}-\d{4}", result), f"Format broken: {result}"

    def test_phone_format_preserved(self):
        phone = "(555) 867-5309"
        params = {"key": TEST_KEY, "tweak": TEST_TWEAK_SSN}

        result = self.enc.operate(phone, params)

        import re
        assert re.fullmatch(r"\(\d{3}\) \d{3}-\d{4}", result), f"Format broken: {result}"


class TestFPEDeterminism:
    """Same input with same key/tweak must always produce the same output."""

    def test_same_input_same_output(self):
        enc = FPEAnonymizer()
        ssn = "123-45-6789"
        params = {"key": TEST_KEY, "tweak": TEST_TWEAK_SSN}

        result1 = enc.operate(ssn, params)
        result2 = enc.operate(ssn, params)

        assert result1 == result2

    def test_different_tweak_different_output(self):
        enc = FPEAnonymizer()
        ssn = "123-45-6789"

        result1 = enc.operate(ssn, {"key": TEST_KEY, "tweak": TEST_TWEAK_SSN})
        result2 = enc.operate(ssn, {"key": TEST_KEY, "tweak": TEST_TWEAK_CC})

        assert result1 != result2


class TestFPEWithMappingStore:
    """FPE operator should store and reuse mappings."""

    def test_stores_mapping(self):
        store = MappingStore()
        enc = FPEAnonymizer()
        ssn = "123-45-6789"
        params = {
            "key": TEST_KEY,
            "tweak": TEST_TWEAK_SSN,
            "entity_type": "US_SSN",
            "mapping_store": store,
        }

        result = enc.operate(ssn, params)

        assert store.get_surrogate("US_SSN", ssn) == result
        assert store.get_real_value("US_SSN", result) == ssn

    def test_reuses_existing_mapping(self):
        store = MappingStore()
        enc = FPEAnonymizer()
        ssn = "123-45-6789"
        params = {
            "key": TEST_KEY,
            "tweak": TEST_TWEAK_SSN,
            "entity_type": "US_SSN",
            "mapping_store": store,
        }

        result1 = enc.operate(ssn, params)
        result2 = enc.operate(ssn, params)

        assert result1 == result2


class TestDeterministicFaker:
    """DeterministicFakerAnonymizer must produce consistent fake values."""

    def test_same_name_same_output(self):
        store = MappingStore()
        faker_op = DeterministicFakerAnonymizer()
        params = {
            "key": "test-secret-key",
            "entity_type": "PERSON",
            "mapping_store": store,
        }

        result1 = faker_op.operate("John Smith", params)
        result2 = faker_op.operate("John Smith", params)

        assert result1 == result2
        assert result1 != "John Smith"

    def test_different_names_different_output(self):
        store = MappingStore()
        faker_op = DeterministicFakerAnonymizer()

        result1 = faker_op.operate("John Smith", {
            "key": "test-key", "entity_type": "PERSON", "mapping_store": store,
        })
        result2 = faker_op.operate("Jane Doe", {
            "key": "test-key", "entity_type": "PERSON", "mapping_store": store,
        })

        assert result1 != result2

    def test_email_produces_email(self):
        store = MappingStore()
        faker_op = DeterministicFakerAnonymizer()
        params = {
            "key": "test-key",
            "entity_type": "EMAIL_ADDRESS",
            "mapping_store": store,
        }

        result = faker_op.operate("john@example.com", params)

        assert "@" in result

    def test_stores_mapping_for_reverse(self):
        store = MappingStore()
        faker_op = DeterministicFakerAnonymizer()
        params = {
            "key": "test-key",
            "entity_type": "PERSON",
            "mapping_store": store,
        }

        result = faker_op.operate("John Smith", params)

        assert store.get_surrogate("PERSON", "John Smith") == result
        assert store.get_real_value("PERSON", result) == "John Smith"


class TestMappingDeanonymizer:
    """MappingDeanonymizer should reverse surrogates via the store."""

    def test_reverse_lookup(self):
        store = MappingStore()
        store.store("PERSON", "John Smith", "FakeName McFake")

        deanon = MappingDeanonymizer()
        result = deanon.operate("FakeName McFake", {
            "mapping_store": store,
            "entity_type": "PERSON",
        })

        assert result == "John Smith"

    def test_cross_entity_fallback(self):
        store = MappingStore()
        store.store("PERSON", "John Smith", "FakeName McFake")

        deanon = MappingDeanonymizer()
        # Look up with wrong entity type — should still find it via cross-entity search
        result = deanon.operate("FakeName McFake", {
            "mapping_store": store,
            "entity_type": "UNKNOWN",
        })

        assert result == "John Smith"

    def test_unknown_surrogate_passthrough(self):
        store = MappingStore()
        deanon = MappingDeanonymizer()

        result = deanon.operate("no-such-surrogate", {
            "mapping_store": store,
            "entity_type": "PERSON",
        })

        assert result == "no-such-surrogate"


class TestOperatorValidation:
    """Operators should raise on missing required params."""

    def test_fpe_requires_key(self):
        with pytest.raises(ValueError, match="key"):
            FPEAnonymizer().validate({"tweak": "abc"})

    def test_fpe_requires_tweak(self):
        with pytest.raises(ValueError, match="tweak"):
            FPEAnonymizer().validate({"key": "abc"})

    def test_faker_requires_key(self):
        with pytest.raises(ValueError, match="key"):
            DeterministicFakerAnonymizer().validate({})

    def test_mapping_deanon_requires_store(self):
        with pytest.raises(ValueError, match="mapping_store"):
            MappingDeanonymizer().validate({})
