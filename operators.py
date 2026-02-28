"""Custom Presidio operators for deterministic, format-preserving PII anonymization.

Operators:
  - FPEAnonymizer:  Format-Preserving Encryption for numeric PII (SSN, CC#, phone)
  - FPEDeanonymizer: Reverse of FPEAnonymizer
  - DeterministicFakerAnonymizer: HMAC-seeded Faker for names, emails, locations
  - MappingDeanonymizer: Reverses any surrogate via the MappingStore
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import TYPE_CHECKING, Dict

from faker import Faker
from ff3 import FF3Cipher
from presidio_anonymizer.operators import Operator, OperatorType

if TYPE_CHECKING:
    from mapping_store import MappingStore


# ── Helpers ───────────────────────────────────────────────────────────────

def _strip_non_digits(text: str) -> tuple[str, list[tuple[int, str]]]:
    """Strip non-digit characters, returning digits and a list of (position, char) separators."""
    separators: list[tuple[int, str]] = []
    digits: list[str] = []
    for i, ch in enumerate(text):
        if ch.isdigit():
            digits.append(ch)
        else:
            separators.append((i, ch))
    return "".join(digits), separators


def _reinsert_separators(digits: str, separators: list[tuple[int, str]]) -> str:
    """Reinsert separator characters at their original positions."""
    result = list(digits)
    for pos, ch in separators:
        result.insert(pos, ch)
    return "".join(result)


# ── FPE Anonymizer ────────────────────────────────────────────────────────

class FPEAnonymizer(Operator):
    """Format-Preserving Encryption anonymizer for numeric PII.

    Encrypts the digit portion of the value while preserving formatting
    characters (dashes, spaces, parens). Deterministic: same input + key + tweak
    always produces the same output.

    Required params: key (hex str), tweak (hex str)
    Optional params: mapping_store (MappingStore instance)
    """

    def operate(self, text: str, params: Dict = None) -> str:
        params = params or {}
        key: str = params["key"]
        tweak: str = params["tweak"]
        entity_type: str = params.get("entity_type", "UNKNOWN")
        mapping_store: MappingStore | None = params.get("mapping_store")

        # Check if we already have a surrogate for this value
        if mapping_store:
            existing = mapping_store.get_surrogate(entity_type, text)
            if existing is not None:
                return existing

        digits, separators = _strip_non_digits(text)
        if len(digits) < 6:
            # FF3 requires minimum 6 digits for radix 10; pad and trim later
            padded = digits.zfill(6)
            cipher = FF3Cipher(key, tweak, radix=10)
            encrypted_padded = cipher.encrypt(padded)
            # Trim back to original length, taking from the right
            encrypted = encrypted_padded[len(encrypted_padded) - len(digits):]
        else:
            cipher = FF3Cipher(key, tweak, radix=10)
            encrypted = cipher.encrypt(digits)

        result = _reinsert_separators(encrypted, separators)

        if mapping_store:
            mapping_store.store(entity_type, text, result)

        return result

    def validate(self, params: Dict = None) -> None:
        params = params or {}
        if "key" not in params:
            raise ValueError("FPEAnonymizer requires 'key' param (hex string)")
        if "tweak" not in params:
            raise ValueError("FPEAnonymizer requires 'tweak' param (hex string)")

    def operator_name(self) -> str:
        return "fpe"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


# ── FPE Deanonymizer ─────────────────────────────────────────────────────

class FPEDeanonymizer(Operator):
    """Reverse of FPEAnonymizer — decrypts FPE-encrypted numeric values."""

    def operate(self, text: str, params: Dict = None) -> str:
        params = params or {}
        key: str = params["key"]
        tweak: str = params["tweak"]

        digits, separators = _strip_non_digits(text)
        if len(digits) < 6:
            padded = digits.zfill(6)
            cipher = FF3Cipher(key, tweak, radix=10)
            decrypted_padded = cipher.decrypt(padded)
            decrypted = decrypted_padded[len(decrypted_padded) - len(digits):]
        else:
            cipher = FF3Cipher(key, tweak, radix=10)
            decrypted = cipher.decrypt(digits)

        return _reinsert_separators(decrypted, separators)

    def validate(self, params: Dict = None) -> None:
        params = params or {}
        if "key" not in params:
            raise ValueError("FPEDeanonymizer requires 'key' param")
        if "tweak" not in params:
            raise ValueError("FPEDeanonymizer requires 'tweak' param")

    def operator_name(self) -> str:
        return "fpe_decrypt"

    def operator_type(self) -> OperatorType:
        return OperatorType.Deanonymize


# ── Deterministic Faker Anonymizer ────────────────────────────────────────

# Mapping from entity type to Faker method name
_FAKER_METHODS: dict[str, str] = {
    "PERSON": "name",
    "EMAIL_ADDRESS": "email",
    "LOCATION": "city",
    "ADDRESS": "address",
    "ORGANIZATION": "company",
    "URL": "url",
}


class DeterministicFakerAnonymizer(Operator):
    """Generates deterministic fake values using HMAC-seeded Faker.

    Same real value + key always maps to the same fake value.
    Requires a MappingStore for reverse lookup (Faker is one-way).

    Required params: key (str or bytes), mapping_store (MappingStore)
    """

    def operate(self, text: str, params: Dict = None) -> str:
        params = params or {}
        key: str | bytes = params["key"]
        entity_type: str = params.get("entity_type", "PERSON")
        mapping_store: MappingStore | None = params.get("mapping_store")

        # Check existing mapping first
        if mapping_store:
            existing = mapping_store.get_surrogate(entity_type, text)
            if existing is not None:
                return existing

        # Derive a deterministic seed from HMAC(key, entity_type + ":" + text)
        if isinstance(key, str):
            key = key.encode()
        mac = hmac.new(key, f"{entity_type}:{text}".encode(), hashlib.sha256)
        seed = int.from_bytes(mac.digest()[:4], "big")

        faker = Faker()
        Faker.seed(seed)

        method_name = _FAKER_METHODS.get(entity_type, "name")
        fake_value: str = getattr(faker, method_name)()

        if mapping_store:
            mapping_store.store(entity_type, text, fake_value)

        return fake_value

    def validate(self, params: Dict = None) -> None:
        params = params or {}
        if "key" not in params:
            raise ValueError("DeterministicFakerAnonymizer requires 'key' param")

    def operator_name(self) -> str:
        return "deterministic_faker"

    def operator_type(self) -> OperatorType:
        return OperatorType.Anonymize


# ── Mapping Deanonymizer ─────────────────────────────────────────────────

class MappingDeanonymizer(Operator):
    """Reverses any surrogate by looking it up in the MappingStore.

    Works for both FPE and Faker surrogates.

    Required params: mapping_store (MappingStore), entity_type (str)
    """

    def operate(self, text: str, params: Dict = None) -> str:
        params = params or {}
        mapping_store: MappingStore = params["mapping_store"]
        entity_type: str = params.get("entity_type", "UNKNOWN")

        real = mapping_store.get_real_value(entity_type, text)
        if real is not None:
            return real

        # Try cross-entity-type search as fallback
        result = mapping_store.has_surrogate_anywhere(text)
        if result is not None:
            return result[1]

        # No mapping found — return as-is
        return text

    def validate(self, params: Dict = None) -> None:
        params = params or {}
        if "mapping_store" not in params:
            raise ValueError("MappingDeanonymizer requires 'mapping_store' param")

    def operator_name(self) -> str:
        return "mapping_deanonymize"

    def operator_type(self) -> OperatorType:
        return OperatorType.Deanonymize
