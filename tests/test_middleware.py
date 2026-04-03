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


class FakeToolResult:
    """Simulates a FastMCP ToolResult with content and structured_content."""
    def __init__(self, content, structured_content=None):
        self.content = content
        self.structured_content = structured_content

    def model_copy(self, update=None):
        new = FakeToolResult(
            content=update.get("content", self.content) if update else self.content,
            structured_content=update.get("structured_content", self.structured_content) if update else self.structured_content,
        )
        return new


class TestStructuredContentMasking:
    """Ensure PII is masked in structured_content, not just text content."""

    def setup_method(self):
        self.store = MappingStore()
        self.mw = PrivacyMiddleware(
            policy=make_policy(),
            mapping_store=self.store,
            fpe_key=TEST_KEY,
        )

    @pytest.mark.asyncio
    async def test_masks_pii_in_structured_content(self):
        """structured_content with PII should be masked — this is the field
        that MCP clients like Claude Code read instead of text content."""
        from mcp.types import TextContent
        context = FakeContext(FakeMessage("get_issue", {"id": "1"}))

        async def call_next(ctx):
            return FakeToolResult(
                content=[TextContent(type="text", text='{"name": "John Smith", "email": "john@example.com"}')],
                structured_content={
                    "name": "John Smith",
                    "email": "john@example.com",
                    "role": "engineer",
                },
            )

        result = await self.mw.on_call_tool(context, call_next)

        # Text content should be masked
        assert "John Smith" not in result.content[0].text

        # structured_content MUST also be masked
        assert result.structured_content is not None
        assert result.structured_content["name"] != "John Smith"
        assert result.structured_content["email"] != "john@example.com"
        # Non-PII fields should be unchanged
        assert result.structured_content["role"] == "engineer"

    @pytest.mark.asyncio
    async def test_structured_content_none_passthrough(self):
        """When structured_content is None, no error should occur."""
        from mcp.types import TextContent
        context = FakeContext(FakeMessage("get_item", {}))

        async def call_next(ctx):
            return FakeToolResult(
                content=[TextContent(type="text", text="No PII here")],
                structured_content=None,
            )

        result = await self.mw.on_call_tool(context, call_next)
        assert result.content[0].text == "No PII here"
        assert result.structured_content is None

    @pytest.mark.asyncio
    async def test_structured_content_nested_pii(self):
        """PII in nested structured_content objects should be masked."""
        from mcp.types import TextContent
        context = FakeContext(FakeMessage("get_issue", {}))

        async def call_next(ctx):
            return FakeToolResult(
                content=[TextContent(type="text", text="ticket data")],
                structured_content={
                    "assignee": {
                        "name": "Jane Doe",
                        "email": "jane.doe@company.com",
                    },
                    "requester": {
                        "name": "Bob Wilson",
                        "email": "bob@client.org",
                    },
                    "title": "Bug report",
                },
            )

        result = await self.mw.on_call_tool(context, call_next)

        sc = result.structured_content
        assert sc["assignee"]["name"] != "Jane Doe"
        assert sc["assignee"]["email"] != "jane.doe@company.com"
        assert sc["requester"]["name"] != "Bob Wilson"
        assert sc["requester"]["email"] != "bob@client.org"
        assert sc["title"] == "Bug report"

    @pytest.mark.asyncio
    async def test_structured_content_deterministic(self):
        """Same PII in structured_content and text content should produce same surrogates."""
        from mcp.types import TextContent
        context = FakeContext(FakeMessage("get_issue", {}))

        async def call_next(ctx):
            return FakeToolResult(
                content=[TextContent(type="text", text="Contact: John Smith john@example.com")],
                structured_content={
                    "name": "John Smith",
                    "email": "john@example.com",
                },
            )

        result = await self.mw.on_call_tool(context, call_next)

        # The surrogate name in structured_content should match text content
        sc_name = result.structured_content["name"]
        assert sc_name != "John Smith"
        assert sc_name in result.content[0].text
