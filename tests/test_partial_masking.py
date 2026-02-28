"""Tests for partial-mask reconciliation in the middleware pipeline.

Verifies that when an upstream API returns a partially masked value
(e.g., '***-**-6789'), the proxy can match it to a previously-seen
full value and return the same surrogate.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import PolicyConfig, EntityPolicy
from mapping_store import MappingStore
from middleware import PrivacyMiddleware

TEST_KEY = "EF4359D8D580AA4F7F036D6F04FC6A94"


def make_policy() -> PolicyConfig:
    return PolicyConfig(
        entities={
            "US_SSN": EntityPolicy(operator="fpe", tweak="CBD09280979564"),
            "CREDIT_CARD": EntityPolicy(operator="fpe", tweak="A1B2C3D4E5F6A7"),
            "DEFAULT": EntityPolicy(operator="replace", new_value="<REDACTED>"),
        },
    )


class FakeMessage:
    def __init__(self, name: str, arguments: dict[str, Any] | None = None):
        self.name = name
        self.arguments = arguments


class FakeContext:
    def __init__(self, message: FakeMessage, fastmcp_context=None):
        self.message = message
        self.fastmcp_context = fastmcp_context

    def copy(self, **kwargs):
        return FakeContext(
            message=kwargs.get("message", self.message),
            fastmcp_context=kwargs.get("fastmcp_context", self.fastmcp_context),
        )


class TestPartialMaskReconciliation:
    """Partially masked values from upstream should map to the same surrogate as the full value."""

    def setup_method(self):
        self.store = MappingStore()
        self.mw = PrivacyMiddleware(
            policy=make_policy(),
            mapping_store=self.store,
            fpe_key=TEST_KEY,
        )

    @pytest.mark.asyncio
    async def test_partial_ssn_maps_to_same_surrogate(self):
        """First see a full SSN, then a partial — both should produce the same surrogate."""
        ctx = FakeContext(FakeMessage("tool", {}))

        # First call: full SSN
        async def call_next_full(c):
            return "Employee SSN: 456-78-9012"

        result1 = await self.mw.on_call_tool(ctx, call_next_full)
        surrogate = self.store.get_surrogate("US_SSN", "456-78-9012")
        assert surrogate is not None

        # Second call: partial SSN from a different API
        async def call_next_partial(c):
            return "Masked SSN: ***-**-9012"

        result2 = await self.mw.on_call_tool(ctx, call_next_partial)

        # The partial should have been reconciled to the same surrogate
        assert surrogate in result2

    @pytest.mark.asyncio
    async def test_partial_cc_maps_to_same_surrogate(self):
        """Partial credit card number should reconcile to a previously seen full number."""
        ctx = FakeContext(FakeMessage("tool", {}))

        async def call_next_full(c):
            return "Card: 4111-1111-1111-1111"

        await self.mw.on_call_tool(ctx, call_next_full)
        surrogate = self.store.get_surrogate("CREDIT_CARD", "4111-1111-1111-1111")
        assert surrogate is not None

        async def call_next_partial(c):
            return "Card ending in XXXX-XXXX-XXXX-1111"

        result = await self.mw.on_call_tool(ctx, call_next_partial)
        assert surrogate in result

    @pytest.mark.asyncio
    async def test_partial_without_prior_full_not_reconciled(self):
        """If we haven't seen the full value, partial can't be reconciled."""
        ctx = FakeContext(FakeMessage("tool", {}))

        async def call_next_partial(c):
            return "SSN: ***-**-9999"

        result = await self.mw.on_call_tool(ctx, call_next_partial)

        # Should not crash; the partial just passes through (or gets masked as-is)
        assert "9999" in result  # partial digits still visible somehow


class TestPartialMaskEdgeCases:
    """Edge cases for partial mask reconciliation."""

    def setup_method(self):
        self.store = MappingStore()
        self.mw = PrivacyMiddleware(
            policy=make_policy(),
            mapping_store=self.store,
            fpe_key=TEST_KEY,
        )

    @pytest.mark.asyncio
    async def test_multiple_partials_in_same_text(self):
        """Text with multiple partial SSNs should reconcile each independently."""
        self.store.store("US_SSN", "456-78-9012", "aaa-bb-cccc")
        self.store.store("US_SSN", "321-54-9876", "xxx-yy-zzzz")

        ctx = FakeContext(FakeMessage("tool", {}))

        async def call_next(c):
            return "SSN1: ***-**-9012 and SSN2: ***-**-9876"

        result = await self.mw.on_call_tool(ctx, call_next)

        assert "aaa-bb-cccc" in result
        assert "xxx-yy-zzzz" in result
