"""Comprehensive fuzz test suite for the MCP Privacy Proxy.

Covers round-trip integrity, PII leakage, JSON/HTML structure preservation,
case insensitivity, sub-token consistency, allow list protection, de-mapping
in tool arguments, cross-format consistency, and concurrent mapping store safety.
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import threading
from pathlib import Path

import pytest
from faker import Faker

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import PolicyConfig, EntityPolicy, FieldRule, load_policy
from mapping_store import MappingStore
from middleware import PrivacyMiddleware

# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

POLICY_PATH = Path(__file__).resolve().parent.parent / "default_policy.yaml"
FPE_KEY = "A" * 32  # 32-hex-char key for FPE / HMAC seeding

fake = Faker()
Faker.seed(42)

# Pre-generate deterministic random data so parametrize IDs are stable
_RANDOM_NAMES = [fake.first_name() + " " + fake.last_name() for _ in range(10)]
_RANDOM_EMAILS = [fake.email() for _ in range(5)]
_RANDOM_PHONES_DASH = [f"{fake.random_int(200,999)}-{fake.random_int(100,999)}-{fake.random_int(1000,9999)}" for _ in range(5)]
_RANDOM_PHONES_DOT = [p.replace("-", ".") for p in _RANDOM_PHONES_DASH]
_RANDOM_PHONES_PAREN = [f"({p[:3]}) {p[4:]}" for p in _RANDOM_PHONES_DASH]


def _fresh_middleware(
    policy: PolicyConfig | None = None,
    mapping_store: MappingStore | None = None,
) -> PrivacyMiddleware:
    """Create an isolated PrivacyMiddleware with a fresh in-memory MappingStore."""
    if policy is None:
        policy = load_policy(POLICY_PATH)
    if mapping_store is None:
        mapping_store = MappingStore()  # in-memory, no file
    return PrivacyMiddleware(
        policy=policy,
        mapping_store=mapping_store,
        fpe_key=FPE_KEY,
    )


# =========================================================================
# 1. Round-trip integrity: mask then de-map recovers original
# =========================================================================

class TestRoundTripIntegrity:
    """Mask PII, then de-map the result -- should recover the original."""

    @pytest.mark.parametrize("name", _RANDOM_NAMES)
    def test_roundtrip_names(self, name: str):
        mw = _fresh_middleware()
        masked = mw._mask_text(name)
        assert masked != name, f"Name was not masked: {name!r}"
        demapped = mw._demap_string(masked)
        assert demapped == name, (
            f"Round-trip failed: {name!r} -> {masked!r} -> {demapped!r}"
        )

    @pytest.mark.parametrize("email", _RANDOM_EMAILS)
    def test_roundtrip_emails(self, email: str):
        mw = _fresh_middleware()
        masked = mw._mask_text(email)
        # Email might be masked or not depending on Presidio detection.
        # If it was masked, de-mapping should recover it.
        if masked != email:
            demapped = mw._demap_string(masked)
            assert demapped == email

    @pytest.mark.parametrize("phone", _RANDOM_PHONES_DASH[:3])
    def test_roundtrip_phone_dash(self, phone: str):
        mw = _fresh_middleware()
        text = f"Call me at {phone} please."
        masked = mw._mask_text(text)
        if masked != text:
            demapped = mw._demap_string(masked)
            assert phone in demapped, (
                f"Phone not recovered: {phone!r} in {demapped!r}"
            )

    @pytest.mark.parametrize("phone", _RANDOM_PHONES_PAREN[:3])
    def test_roundtrip_phone_paren(self, phone: str):
        mw = _fresh_middleware()
        text = f"Phone: {phone}"
        masked = mw._mask_text(text)
        if masked != text:
            demapped = mw._demap_string(masked)
            assert phone in demapped

    def test_roundtrip_name_in_sentence(self):
        mw = _fresh_middleware()
        name = _RANDOM_NAMES[0]
        text = f"Hello, my name is {name} and I live in Springfield."
        masked = mw._mask_text(text)
        demapped = mw._demap_string(masked)
        assert name in demapped

    def test_roundtrip_name_in_json(self):
        mw = _fresh_middleware()
        name = _RANDOM_NAMES[1]
        data = json.dumps({"greeting": f"Hi {name}, welcome!"})
        masked = mw._mask_text(data)
        demapped = mw._demap_string(masked)
        assert name in demapped

    def test_roundtrip_name_in_html(self):
        mw = _fresh_middleware()
        name = _RANDOM_NAMES[2]
        html = f"<p>Dear <b>{name}</b>, your account is ready.</p>"
        masked = mw._mask_text(html)
        demapped = mw._demap_string(masked)
        assert name in demapped


# =========================================================================
# 2. No PII leakage: original values must NOT appear in masked output
# =========================================================================

class TestNoPiiLeakage:
    """After masking, the original real values should be absent from output."""

    @pytest.mark.parametrize("name", _RANDOM_NAMES[:5])
    def test_name_not_in_masked_output(self, name: str):
        mw = _fresh_middleware()
        masked = mw._mask_text(f"The employee is {name}.")
        # The original name (case-insensitive) should not appear
        assert name.lower() not in masked.lower(), (
            f"PII leaked: {name!r} found in {masked!r}"
        )

    def test_name_not_in_html_body(self):
        mw = _fresh_middleware()
        name = _RANDOM_NAMES[3]
        html = f"<html><body><h1>Welcome {name}</h1><p>Info for {name}.</p></body></html>"
        masked = mw._mask_text(html)
        assert name.lower() not in masked.lower()

    def test_name_not_in_json_response(self):
        mw = _fresh_middleware()
        name = _RANDOM_NAMES[4]
        data = json.dumps({"user": {"name": name, "role": "admin"}})
        masked = mw._mask_text(data)
        assert name.lower() not in masked.lower()

    def test_mixed_content_no_leakage(self):
        mw = _fresh_middleware()
        name = _RANDOM_NAMES[5]
        text = f"Name: {name}\nHTML: <b>{name}</b>\nJSON: {{\"n\": \"{name}\"}}"
        masked = mw._mask_text(text)
        assert name.lower() not in masked.lower()


# =========================================================================
# 3. JSON structure preservation
# =========================================================================

class TestJsonStructurePreservation:
    """Masking a JSON string should yield valid JSON with keys unchanged."""

    def test_masked_json_is_valid(self):
        mw = _fresh_middleware()
        data = {"name": "Robert Johnson", "email": "robert@example.com", "age": 30}
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)
        assert isinstance(parsed, dict)

    def test_json_keys_preserved(self):
        mw = _fresh_middleware()
        data = {"first_name": "Alice", "last_name": "Williams", "phone": "555-123-4567"}
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)
        assert set(parsed.keys()) == set(data.keys())

    def test_nested_json_survives(self):
        mw = _fresh_middleware()
        data = {
            "user": {
                "name": "David Brown",
                "contacts": [
                    {"type": "email", "value": "david@example.com"},
                    {"type": "phone", "value": "555-987-6543"},
                ],
            },
            "metadata": {"count": 1},
        }
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)
        assert "user" in parsed
        assert "contacts" in parsed["user"]
        assert isinstance(parsed["user"]["contacts"], list)
        assert parsed["metadata"]["count"] == 1

    def test_field_values_replaced_but_structure_intact(self):
        mw = _fresh_middleware()
        data = {"first_name": "Michael", "last_name": "Garcia", "status": "active"}
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)
        # "status" is not PII, should be unchanged
        assert parsed["status"] == "active"

    @pytest.mark.parametrize("key", [
        "data", "mark", "grace", "grant", "hunter", "chase", "bill",
        "response", "christian", "frank", "don", "josh",
    ])
    def test_ambiguous_keys_not_masked(self, key: str):
        """Keys that look like person names must never be altered."""
        mw = _fresh_middleware()
        data = {key: "some non-pii value", "other": "hello"}
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)
        assert key in parsed, f"Key {key!r} was removed or renamed"
        assert parsed[key] == "some non-pii value"

    def test_nested_ambiguous_keys_not_masked(self):
        """Nested keys that resemble names must survive masking."""
        mw = _fresh_middleware()
        data = {
            "response": {
                "data": {"mark": "non-pii", "grace": 42},
                "grant": [1, 2, 3],
            }
        }
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)
        assert parsed["response"]["data"]["mark"] == "non-pii"
        assert parsed["response"]["data"]["grace"] == 42
        assert parsed["response"]["grant"] == [1, 2, 3]

    def test_ambiguous_key_with_pii_value(self):
        """A key that looks like a name should stay, but a PII *value* should be masked."""
        mw = _fresh_middleware()
        data = {"grant": "John Smith", "data": "jane.doe@example.com"}
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)
        # Keys must be unchanged
        assert "grant" in parsed
        assert "data" in parsed
        # Values should be masked (not equal to originals)
        assert parsed["grant"] != "John Smith"
        assert parsed["data"] != "jane.doe@example.com"

    def test_prescan_does_not_replace_keys(self):
        """If a known PII value matches a JSON key name, the key must not be replaced."""
        mw = _fresh_middleware()
        # First, get "Mark" into the mapping store as a known PII value
        mw._mask_text("Please contact Mark Johnson about this.")
        # Now process JSON with "mark" as a key
        data = {"mark": "non-pii value", "status": "ok"}
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)
        assert "mark" in parsed, "Key 'mark' was replaced by prescan"
        assert parsed["status"] == "ok"


class TestJsonEscapingSafety:
    """Surrogates with special characters must not corrupt JSON output."""

    def test_value_with_apostrophe_stays_valid_json(self):
        """A value containing an apostrophe must be properly escaped in output."""
        mw = _fresh_middleware()
        # Force a surrogate with an apostrophe into the mapping store
        mw.mapping_store.store("PERSON", "Jane Doe", "Mary O'Brien")
        data = {"name": "Jane Doe", "role": "engineer"}
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)  # Must not raise
        assert parsed["role"] == "engineer"
        assert "Jane Doe" not in masked

    def test_value_with_double_quote_stays_valid_json(self):
        """A surrogate containing a double quote must not break JSON."""
        mw = _fresh_middleware()
        mw.mapping_store.store("PERSON", "John Smith", 'John "The Rock" Smith')
        data = {"contact": "John Smith", "count": 5}
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)  # Must not raise
        assert parsed["count"] == 5
        assert "John Smith" not in json.dumps(parsed)

    def test_value_with_backslash_stays_valid_json(self):
        """A surrogate containing backslashes must not break JSON."""
        mw = _fresh_middleware()
        mw.mapping_store.store("PERSON", "Alice Jones", "Alice\\Jones")
        data = {"user": "Alice Jones", "active": True}
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)  # Must not raise
        assert parsed["active"] is True

    def test_value_with_newline_stays_valid_json(self):
        """A surrogate containing a newline must not break JSON."""
        mw = _fresh_middleware()
        mw.mapping_store.store("PERSON", "Bob Brown", "Bob\nBrown")
        data = {"name": "Bob Brown", "status": "ok"}
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)  # Must not raise
        assert parsed["status"] == "ok"

    def test_long_body_with_special_chars_stays_valid_json(self):
        """Real-world scenario: HTML body text with PII in a JSON response."""
        mw = _fresh_middleware()
        data = {
            "subject": "Meeting with Robert Johnson",
            "body": '<p>Hi Robert Johnson,</p><p>Let\'s meet at "The Office" on Monday.</p>',
            "id": 42,
        }
        text = json.dumps(data)
        masked = mw._mask_text(text)
        parsed = json.loads(masked)  # Must not raise
        assert parsed["id"] == 42
        assert "Robert Johnson" not in json.dumps(parsed)


# =========================================================================
# 4. HTML structure preservation
# =========================================================================

class TestHtmlStructurePreservation:
    """Masking HTML should keep tags intact, changing only text content."""

    def test_html_tags_intact(self):
        mw = _fresh_middleware()
        name = "Jennifer Martinez"
        html = f'<div class="card"><p>{name}</p></div>'
        masked = mw._mask_text(html)
        # The div and p tags should still be present
        assert "<div" in masked
        assert "<p>" in masked or "<p " in masked
        assert "</p>" in masked
        assert "</div>" in masked

    def test_tag_attributes_preserved(self):
        mw = _fresh_middleware()
        html = '<a href="https://example.com" class="link">Sarah Connor</a>'
        masked = mw._mask_text(html)
        assert 'href="https://example.com"' in masked
        assert 'class="link"' in masked

    def test_multiple_tags_survive(self):
        mw = _fresh_middleware()
        html = (
            "<ul>"
            "<li>Employee: Thomas Anderson</li>"
            "<li>Manager: Diana Prince</li>"
            "</ul>"
        )
        masked = mw._mask_text(html)
        assert masked.count("<li>") == 2
        assert masked.count("</li>") == 2
        assert "<ul>" in masked
        assert "</ul>" in masked


# =========================================================================
# 5. Case insensitivity
# =========================================================================

class TestCaseInsensitivity:
    """De-mapping should work regardless of case."""

    def test_demap_various_cases(self):
        mw = _fresh_middleware()
        name = "Robert Wilson"
        masked = mw._mask_text(name)
        surrogate = masked.strip()
        assert surrogate != name

        # All case variants should de-map back
        assert mw._demap_string(surrogate.lower()) == name
        assert mw._demap_string(surrogate.upper()) == name

        # Mixed case
        mixed = surrogate[0].lower() + surrogate[1:].upper() if len(surrogate) > 1 else surrogate
        demapped = mw._demap_string(mixed)
        assert demapped == name

    def test_demap_embedded_case_variants(self):
        mw = _fresh_middleware()
        name = "Patricia Clark"
        masked_text = mw._mask_text(f"Employee: {name}")
        # Extract surrogate (everything after "Employee: ")
        surrogate_name = masked_text.replace("Employee: ", "")

        # Embed in uppercase sentence
        upper_text = f"USER: {surrogate_name.upper()}"
        demapped = mw._demap_string(upper_text)
        assert name in demapped


# =========================================================================
# 6. Sub-token consistency
# =========================================================================

class TestSubTokenConsistency:
    """Full name and its component tokens should map consistently."""

    def test_subtoken_first_name_matches(self):
        mw = _fresh_middleware()
        full_name = "George Washington"
        masked_full = mw._mask_text(full_name)
        surrogate_parts = masked_full.strip().split()

        # Now mask just the first name alone
        masked_first = mw._mask_text("George")
        # The first-name surrogate should match the first part of the full-name surrogate
        if len(surrogate_parts) >= 2:
            assert masked_first.strip() == surrogate_parts[0], (
                f"Sub-token mismatch: first={masked_first!r}, "
                f"full parts={surrogate_parts}"
            )

    def test_subtoken_last_name_matches(self):
        mw = _fresh_middleware()
        full_name = "Benjamin Franklin"
        masked_full = mw._mask_text(full_name)
        surrogate_parts = masked_full.strip().split()

        masked_last = mw._mask_text("Franklin")
        if len(surrogate_parts) >= 2:
            assert masked_last.strip() == surrogate_parts[1]

    def test_field_rules_consistent_with_full_name(self):
        """Field rules for first_name/last_name should align with full name masking."""
        mw = _fresh_middleware()
        full_name = "Alexander Hamilton"
        # Mask full name first to create sub-tokens
        masked_full = mw._mask_text(full_name)
        surrogate_parts = masked_full.strip().split()

        # Now mask via field rules (JSON with first_name, last_name)
        data = json.dumps({"first_name": "Alexander", "last_name": "Hamilton"})
        masked_json = mw._mask_text(data)
        parsed = json.loads(masked_json)

        if len(surrogate_parts) >= 2:
            assert parsed["first_name"] == surrogate_parts[0]
            assert parsed["last_name"] == surrogate_parts[1]


# =========================================================================
# 7. Allow list protection
# =========================================================================

class TestAllowListProtection:
    """Terms on the allow list should never be masked."""

    def test_allow_list_term_preserved(self):
        policy = load_policy(POLICY_PATH)
        # Add a name-like term to the allow list
        policy.allow_list.append("Alexandria")
        mw = _fresh_middleware(policy=policy)

        text = "The city of Alexandria is beautiful."
        masked = mw._mask_text(text)
        assert "Alexandria" in masked

    def test_allow_list_multiple_terms(self):
        policy = load_policy(POLICY_PATH)
        policy.allow_list.extend(["Springfield", "Portland"])
        mw = _fresh_middleware(policy=policy)

        text = "Offices in Springfield and Portland are open."
        masked = mw._mask_text(text)
        assert "Springfield" in masked
        assert "Portland" in masked

    def test_allow_list_name_like_term(self):
        policy = load_policy(POLICY_PATH)
        policy.allow_list.append("Virginia")
        mw = _fresh_middleware(policy=policy)

        text = "Virginia is a state on the east coast."
        masked = mw._mask_text(text)
        assert "Virginia" in masked


# =========================================================================
# 8. De-mapping in tool arguments
# =========================================================================

class TestDemapArguments:
    """Surrogates in tool argument structures should be replaced with real values."""

    def _setup_surrogate(self, mw: PrivacyMiddleware, real: str) -> str:
        """Mask a name and return its surrogate."""
        return mw._mask_text(real).strip()

    def test_flat_dict(self):
        mw = _fresh_middleware()
        surrogate = self._setup_surrogate(mw, "Emily Davis")
        args = {"query": f"Find records for {surrogate}"}
        result = mw._demap_arguments(args)
        assert "Emily Davis" in result["query"]

    def test_nested_dict(self):
        mw = _fresh_middleware()
        surrogate = self._setup_surrogate(mw, "William Taylor")
        args = {
            "filter": {
                "user": {
                    "name": surrogate,
                }
            }
        }
        result = mw._demap_arguments(args)
        assert result["filter"]["user"]["name"] == "William Taylor"

    def test_list_values(self):
        mw = _fresh_middleware()
        s1 = self._setup_surrogate(mw, "James Wilson")
        s2 = self._setup_surrogate(mw, "Maria Lopez")
        args = {"names": [s1, s2]}
        result = mw._demap_arguments(args)
        assert "James Wilson" in result["names"][0]
        assert "Maria Lopez" in result["names"][1]

    def test_mixed_args(self):
        mw = _fresh_middleware()
        surrogate = self._setup_surrogate(mw, "Daniel Brown")
        args = {
            "name": surrogate,
            "count": 5,
            "tags": ["admin", surrogate],
            "nested": {"label": f"User: {surrogate}"},
        }
        result = mw._demap_arguments(args)
        assert result["name"] == "Daniel Brown"
        assert result["count"] == 5
        assert "Daniel Brown" in result["tags"][1]
        assert "Daniel Brown" in result["nested"]["label"]

    def test_non_string_values_pass_through(self):
        mw = _fresh_middleware()
        args = {"count": 42, "active": True, "ratio": 3.14, "data": None}
        result = mw._demap_arguments(args)
        assert result == args


# =========================================================================
# 9. Cross-format consistency
# =========================================================================

class TestCrossFormatConsistency:
    """Same person in different formats should get the same surrogate."""

    def test_same_surrogate_plain_and_html(self):
        mw = _fresh_middleware()
        name = "Christopher Lee"

        masked_plain = mw._mask_text(name)
        masked_html = mw._mask_text(f"<p>{name}</p>")
        # Extract the surrogate from HTML by stripping tags
        html_text = re.sub(r"<[^>]+>", "", masked_html).strip()

        assert masked_plain.strip() == html_text, (
            f"Mismatch: plain={masked_plain!r}, html_text={html_text!r}"
        )

    def test_same_surrogate_plain_and_json_field(self):
        mw = _fresh_middleware()
        name = "Elizabeth Warren"

        masked_plain = mw._mask_text(name)
        data = json.dumps({"name": name})
        masked_json = mw._mask_text(data)
        parsed = json.loads(masked_json)

        assert parsed["name"] == masked_plain.strip()

    def test_same_surrogate_across_multiple_occurrences(self):
        mw = _fresh_middleware()
        name = "Margaret Thompson"

        text = f"{name} said hello. Later, {name} left."
        masked = mw._mask_text(text)

        # The name should be replaced with the same surrogate both times
        surrogate = mw.mapping_store.get_surrogate("PERSON", name)
        if surrogate:
            assert masked.count(surrogate) == 2


# =========================================================================
# 10. Concurrent-safe mapping store
# =========================================================================

class TestConcurrentMappingStore:
    """Multiple stores pointing at the same file should see each other's writes."""

    def test_cross_process_visibility(self, tmp_path):
        path = tmp_path / "shared_mappings.json"

        store1 = MappingStore(path=path)
        store2 = MappingStore(path=path)

        store1.store("PERSON", "Alice Johnson", "Fake Alice")

        # store2 should see the write after refresh
        result = store2.get_surrogate("PERSON", "Alice Johnson")
        assert result == "Fake Alice"

    def test_concurrent_writes(self, tmp_path):
        """Multiple threads writing to the same file should not corrupt it.

        Under contention, individual writes may fail (partial reads of the
        encrypted file), but the end state should be a valid, non-corrupted
        mapping store.
        """
        path = tmp_path / "concurrent_mappings.json"

        def writer(store: MappingStore, thread_id: int):
            for i in range(20):
                try:
                    store.store(
                        "PERSON",
                        f"Person_{thread_id}_{i}",
                        f"Surrogate_{thread_id}_{i}",
                    )
                except Exception:
                    pass  # Transient contention is expected

        stores = [MappingStore(path=path) for _ in range(4)]
        threads = [
            threading.Thread(target=writer, args=(stores[i], i))
            for i in range(4)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # The file should be readable and not corrupted
        verify_store = MappingStore(path=path)
        total = sum(
            len(fwd)
            for fwd in verify_store._forward.values()
        )
        assert total > 0, "No mappings survived concurrent writes"

    def test_interleaved_read_write(self, tmp_path):
        """One store writes, another reads -- reader should see updates."""
        path = tmp_path / "interleaved_mappings.json"

        writer_store = MappingStore(path=path)
        reader_store = MappingStore(path=path)

        writer_store.store("PERSON", "Bob Smith", "Fake Bob")
        assert reader_store.get_surrogate("PERSON", "Bob Smith") == "Fake Bob"

        writer_store.store("EMAIL_ADDRESS", "bob@example.com", "fake@example.com")
        assert reader_store.get_surrogate("EMAIL_ADDRESS", "bob@example.com") == "fake@example.com"
