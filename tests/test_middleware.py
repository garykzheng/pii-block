"""End-to-end tests for PrivacyMiddleware with a mock MCP backend."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

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
            "PERSON": EntityPolicy(operator="deterministic_faker"),
            "EMAIL_ADDRESS": EntityPolicy(operator="deterministic_faker"),
            "DEFAULT": EntityPolicy(operator="replace", new_value="<REDACTED>"),
        },
    )


class FakeMessage:
    """Simulates a CallToolRequestParams."""
    def __init__(self, name: str, arguments: dict[str, Any] | None = None):
        self.name = name
        self.arguments = arguments


class FakeContext:
    """Simulates MiddlewareContext."""
    def __init__(self, message: FakeMessage, fastmcp_context=None):
        self.message = message
        self.fastmcp_context = fastmcp_context

    def copy(self, **kwargs):
        new = FakeContext(
            message=kwargs.get("message", self.message),
            fastmcp_context=kwargs.get("fastmcp_context", self.fastmcp_context),
        )
        return new


class TestMiddlewareMaskingInbound:
    """POST-CALL: PII in tool results should be masked."""

    def setup_method(self):
        self.store = MappingStore()
        self.mw = PrivacyMiddleware(
            policy=make_policy(),
            mapping_store=self.store,
            fpe_key=TEST_KEY,
        )

    @pytest.mark.asyncio
    async def test_masks_ssn_in_result(self):
        """Tool result containing an SSN should be FPE-encrypted."""
        context = FakeContext(FakeMessage("get_employee", {"id": "1"}))

        async def call_next(ctx):
            return "Employee SSN: 456-78-9012"

        result = await self.mw.on_call_tool(context, call_next)

        assert "456-78-9012" not in result
        # The surrogate SSN should be stored
        surrogate = self.store.get_surrogate("US_SSN", "456-78-9012")
        assert surrogate is not None
        assert surrogate in result

    @pytest.mark.asyncio
    async def test_masks_person_name_in_result(self):
        """Tool result containing a person name should be Faker-anonymized."""
        context = FakeContext(FakeMessage("get_employee", {"id": "1"}))

        async def call_next(ctx):
            return "The employee is John Smith and he works in accounting."

        result = await self.mw.on_call_tool(context, call_next)

        assert "John Smith" not in result

    @pytest.mark.asyncio
    async def test_deterministic_masking(self):
        """Same PII value should produce the same surrogate across calls."""
        async def call_next_1(ctx):
            return "Contact SSN: 456-78-9012"

        async def call_next_2(ctx):
            return "SSN is 456-78-9012"

        ctx = FakeContext(FakeMessage("tool1", {}))

        result1 = await self.mw.on_call_tool(ctx, call_next_1)
        result2 = await self.mw.on_call_tool(ctx, call_next_2)

        surrogate = self.store.get_surrogate("US_SSN", "456-78-9012")
        assert surrogate in result1
        assert surrogate in result2

    @pytest.mark.asyncio
    async def test_passthrough_no_pii(self):
        """Results without PII should pass through unchanged."""
        context = FakeContext(FakeMessage("list_items", {}))

        async def call_next(ctx):
            return "Item 1: Widget, Item 2: Gadget"

        result = await self.mw.on_call_tool(context, call_next)

        assert result == "Item 1: Widget, Item 2: Gadget"


class TestMiddlewareDeMapOutbound:
    """PRE-CALL: surrogate values in tool arguments should be de-mapped to real values."""

    def setup_method(self):
        self.store = MappingStore()
        self.mw = PrivacyMiddleware(
            policy=make_policy(),
            mapping_store=self.store,
            fpe_key=TEST_KEY,
        )

    @pytest.mark.asyncio
    async def test_demaps_surrogate_in_args(self):
        """If the agent passes a surrogate SSN in tool args, it should be replaced with the real value."""
        # Pre-populate the mapping (as if a previous response was masked)
        self.store.store("US_SSN", "123-45-6789", "987-65-4321")

        captured_args: dict[str, Any] = {}

        async def call_next(ctx):
            captured_args.update(ctx.message.arguments or {})
            return "ok"

        context = FakeContext(FakeMessage("update_ssn", {"ssn": "987-65-4321"}))
        await self.mw.on_call_tool(context, call_next)

        assert captured_args["ssn"] == "123-45-6789"

    @pytest.mark.asyncio
    async def test_demaps_surrogate_in_nested_args(self):
        """Surrogates in nested dict values should also be de-mapped."""
        self.store.store("PERSON", "John Smith", "FakeName")

        captured_args: dict[str, Any] = {}

        async def call_next(ctx):
            captured_args.update(ctx.message.arguments or {})
            return "ok"

        context = FakeContext(FakeMessage("search", {
            "filters": {"name": "FakeName"},
        }))
        await self.mw.on_call_tool(context, call_next)

        assert captured_args["filters"]["name"] == "John Smith"

    @pytest.mark.asyncio
    async def test_no_surrogates_passthrough(self):
        """Args without surrogates should pass through unchanged."""
        captured_args: dict[str, Any] = {}

        async def call_next(ctx):
            captured_args.update(ctx.message.arguments or {})
            return "ok"

        context = FakeContext(FakeMessage("search", {"query": "hello world"}))
        await self.mw.on_call_tool(context, call_next)

        assert captured_args["query"] == "hello world"


class TestMiddlewareListContent:
    """Test handling of list-type tool results (multiple content items)."""

    def setup_method(self):
        self.store = MappingStore()
        self.mw = PrivacyMiddleware(
            policy=make_policy(),
            mapping_store=self.store,
            fpe_key=TEST_KEY,
        )

    @pytest.mark.asyncio
    async def test_masks_list_of_strings(self):
        context = FakeContext(FakeMessage("get_records", {}))

        async def call_next(ctx):
            return ["Record 1: SSN 456-78-9012", "Record 2: SSN 321-54-9876"]

        result = await self.mw.on_call_tool(context, call_next)

        assert isinstance(result, list)
        assert "456-78-9012" not in result[0]
        assert "321-54-9876" not in result[1]

    @pytest.mark.asyncio
    async def test_none_result_passthrough(self):
        context = FakeContext(FakeMessage("noop", {}))

        async def call_next(ctx):
            return None

        result = await self.mw.on_call_tool(context, call_next)

        assert result is None


class TestSurrogateNotice:
    """The proxy should append a privacy notice when PII is masked."""

    def setup_method(self):
        self.store = MappingStore()
        self.mw = PrivacyMiddleware(
            policy=make_policy(),
            mapping_store=self.store,
            fpe_key=TEST_KEY,
        )

    @pytest.mark.asyncio
    async def test_notice_appended_when_pii_masked(self):
        """String results with PII should include the surrogate notice."""
        context = FakeContext(FakeMessage("get_user", {"id": "1"}))

        async def call_next(ctx):
            return "The user is John Smith."

        result = await self.mw.on_call_tool(context, call_next)

        assert "John Smith" not in result
        assert "privacy surrogates" in result

    @pytest.mark.asyncio
    async def test_no_notice_when_no_pii(self):
        """Results without PII should not include the notice."""
        context = FakeContext(FakeMessage("list_items", {}))

        async def call_next(ctx):
            return "Item 1: Widget, Item 2: Gadget"

        result = await self.mw.on_call_tool(context, call_next)

        assert "surrogate" not in result

    @pytest.mark.asyncio
    async def test_notice_disabled_by_policy(self):
        """When surrogate_notice is False, no notice should be appended."""
        policy = make_policy()
        policy.surrogate_notice = False
        mw = PrivacyMiddleware(
            policy=policy,
            mapping_store=MappingStore(),
            fpe_key=TEST_KEY,
        )
        context = FakeContext(FakeMessage("get_user", {"id": "1"}))

        async def call_next(ctx):
            return "The user is John Smith."

        result = await mw.on_call_tool(context, call_next)

        assert "John Smith" not in result
        assert "surrogate" not in result

    @pytest.mark.asyncio
    async def test_notice_appended_to_list_result(self):
        """List results with PII should include the notice as a trailing item."""
        context = FakeContext(FakeMessage("get_records", {}))

        async def call_next(ctx):
            return ["Record: SSN 456-78-9012"]

        result = await self.mw.on_call_tool(context, call_next)

        assert isinstance(result, list)
        assert len(result) == 2
        assert "456-78-9012" not in result[0]
        assert hasattr(result[-1], "text")
        assert "privacy surrogates" in result[-1].text
