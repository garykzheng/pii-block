"""FastMCP Middleware that intercepts tool calls and resources to mask/unmask PII.

PrivacyMiddleware sits in the proxy pipeline and:
  PRE-CALL:  scans tool arguments for known surrogates, replaces with real values
  POST-CALL: detects PII in results, replaces with deterministic surrogates
"""

from __future__ import annotations

import fnmatch
import json
import logging
import re
from html.parser import HTMLParser
from typing import Any, Sequence

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, RecognizerResult

from mcp.types import TextContent
from fastmcp.server.middleware import Middleware, MiddlewareContext

from audit import AuditLog, AuditEvent
from config import PolicyConfig, EntityPolicy
from mapping_store import MappingStore
from operators import (
    FPEAnonymizer,
    DeterministicFakerAnonymizer,
)

logger = logging.getLogger("privacy_middleware")


_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

# Slack identifiers: channel (C), user (U/W), team (T), group (G),
# DM (D), enterprise (E). 9+ alphanumerics in uppercase.
_SLACK_ID_RE = re.compile(r"\b[CUTWGDE][A-Z0-9]{8,}\b")

# Prefix-style IDs (Stripe-shaped): org_*, usr_*, acct_*, cus_*, etc.
# Pattern: 2-8 lowercase letter prefix, underscore, 8+ alphanumerics.
# Body excludes underscores so this doesn't match snake_case English
# like "provider_company_name" or "created_by".
_PREFIX_ID_RE = re.compile(r"\b[a-z]{2,8}_[A-Za-z0-9]{8,}\b")


def _find_uuid_spans(text: str) -> list[tuple[int, int]]:
    """Find character spans of UUIDs in text.

    Used to prevent PII masking from corrupting UUIDs, which sometimes
    contain letter sequences (e.g. "c0a4d5ea") that Presidio's NER
    misdetects as LOCATION or PERSON.
    """
    return [(m.start(), m.end()) for m in _UUID_RE.finditer(text)]


def _find_slack_id_spans(text: str) -> list[tuple[int, int]]:
    """Find character spans of Slack IDs in text.

    Slack channel/user/team/etc. IDs follow the pattern
    ``[CUTWGDE][A-Z0-9]{8+}`` (e.g. C059079JARF, U03N32D0R4P).
    Their first 8 characters can look name-shaped and get misdetected
    by Presidio's NER as PERSON or LOCATION.
    """
    return [(m.start(), m.end()) for m in _SLACK_ID_RE.finditer(text)]


def _find_prefix_id_spans(text: str) -> list[tuple[int, int]]:
    """Find character spans of prefix-style IDs (org_*, usr_*, cus_*, etc.).

    Many APIs use Stripe-style prefixed identifiers like
    ``org_HpE7IuGBi1xFkjHZ`` — these aren't UUIDs but should never be
    treated as PII. Body must be 8+ chars without underscores so this
    pattern doesn't match snake_case English (created_by, etc.).
    """
    return [(m.start(), m.end()) for m in _PREFIX_ID_RE.finditer(text)]


def _find_url_spans(text: str) -> list[tuple[int, int]]:
    """Find character spans of URLs in text.

    Matches http(s) URLs and common bare-domain patterns (e.g. foo.com/bar).
    Used to prevent PII masking from corrupting URLs.
    """
    spans: list[tuple[int, int]] = []
    # Full URLs: http(s)://...
    for m in re.finditer(r'https?://[^\s<>"\')\]]+', text):
        spans.append((m.start(), m.end()))
    # Bare domains: word.tld or word.tld/path (common TLDs only)
    for m in re.finditer(
        r'(?<![@\w])[\w.-]+\.(?:com|org|net|io|app|ai|dev|co|sh|xyz|site|cloud)(?:/[^\s<>"\')\]]*)?',
        text,
    ):
        spans.append((m.start(), m.end()))
    return spans


def _find_json_key_spans(text: str) -> list[tuple[int, int]]:
    """Find character spans of JSON object keys in serialized JSON text.

    Returns a list of (start, end) tuples where each span covers the key
    content *including* its surrounding quotes, e.g. for ``"data":`` the
    span covers the ``"data"`` portion.  This allows callers to check
    whether a Presidio detection or prescan match overlaps a key and skip
    it.

    Only called when the text is known to be valid JSON.
    """
    spans: list[tuple[int, int]] = []
    # Match a quoted string followed by optional whitespace and a colon.
    # The regex handles escaped characters inside the string.
    for m in re.finditer(r'"(?:[^"\\]|\\.)*"\s*:', text):
        # The key string runs from the opening quote to the closing quote
        # (exclude the whitespace + colon).
        key_str = m.group()
        closing_quote = key_str.rindex('"', 1)
        spans.append((m.start(), m.start() + closing_quote + 1))
    return spans


def _overlaps_any_span(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    """Return True if [start, end) overlaps with any span in the list."""
    for s_start, s_end in spans:
        if start < s_end and end > s_start:
            return True
    return False


_BLOCK_TAGS = frozenset({
    "br", "p", "div", "li", "tr", "td", "th", "h1", "h2", "h3", "h4", "h5",
    "h6", "blockquote", "pre", "hr", "table", "thead", "tbody", "ul", "ol",
})


def _strip_html(html: str) -> tuple[str, list[int]]:
    """Strip HTML tags and return (plain_text, offset_map).

    offset_map[i] gives the index in the original HTML string that corresponds
    to plain_text[i]. This allows mapping Presidio detections on the plain text
    back to their positions in the original HTML.

    Block-level tags (br, p, div, etc.) insert a space so that text on either
    side doesn't run together.
    """
    plain_chars: list[str] = []
    offset_map: list[int] = []
    i = 0
    n = len(html)

    while i < n:
        if html[i] == "<":
            # Skip to end of tag
            end = html.find(">", i)
            if end == -1:
                break
            # Check if this is a block-level tag that should insert whitespace
            tag_content = html[i + 1:end].strip().lower()
            # Remove leading / for closing tags
            tag_name = tag_content.lstrip("/").split()[0].split("/")[0] if tag_content else ""
            if tag_name in _BLOCK_TAGS and plain_chars and plain_chars[-1] != " ":
                plain_chars.append(" ")
                offset_map.append(i)
            i = end + 1
        elif html[i] == "&":
            # Decode HTML entity
            semi = html.find(";", i, i + 10)
            if semi != -1:
                entity = html[i:semi + 1]
                if entity == "&#39;":
                    plain_chars.append("'")
                    offset_map.append(i)
                elif entity == "&amp;":
                    plain_chars.append("&")
                    offset_map.append(i)
                elif entity == "&lt;":
                    plain_chars.append("<")
                    offset_map.append(i)
                elif entity == "&gt;":
                    plain_chars.append(">")
                    offset_map.append(i)
                elif entity == "&quot;":
                    plain_chars.append('"')
                    offset_map.append(i)
                elif entity == "&nbsp;":
                    plain_chars.append(" ")
                    offset_map.append(i)
                else:
                    # Unknown entity — keep as-is
                    for j in range(i, semi + 1):
                        plain_chars.append(html[j])
                        offset_map.append(j)
                i = semi + 1
            else:
                plain_chars.append(html[i])
                offset_map.append(i)
                i += 1
        else:
            plain_chars.append(html[i])
            offset_map.append(i)
            i += 1

    return "".join(plain_chars), offset_map


class PrivacyMiddleware(Middleware):
    """Bidirectional PII masking middleware for FastMCP proxies."""

    def __init__(
        self,
        policy: PolicyConfig,
        mapping_store: MappingStore,
        fpe_key: str,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.policy = policy
        self.mapping_store = mapping_store
        self.fpe_key = fpe_key
        self.audit_log = audit_log

        # Presidio analyzer
        self.analyzer = AnalyzerEngine()
        self._register_custom_recognizers()

        # Presidio anonymizer with custom operators
        self.anonymizer = AnonymizerEngine()
        self.anonymizer.add_anonymizer(FPEAnonymizer)
        self.anonymizer.add_anonymizer(DeterministicFakerAnonymizer)

        # Pre-compute the list of entity types we care about
        self._entity_types = [
            et for et in self.policy.entities if et != "DEFAULT"
        ]
        # Add custom recognizer entity types
        for rec in self.policy.custom_recognizers:
            if rec.entity not in self._entity_types:
                self._entity_types.append(rec.entity)

    def _register_custom_recognizers(self) -> None:
        """Register custom regex recognizers from the policy."""
        for rec in self.policy.custom_recognizers:
            pattern = Pattern(
                name=f"{rec.entity}_pattern",
                regex=rec.pattern,
                score=rec.score,
            )
            recognizer = PatternRecognizer(
                supported_entity=rec.entity,
                patterns=[pattern],
            )
            self.analyzer.registry.add_recognizer(recognizer)

    # ── Tool call interception ────────────────────────────────────────────

    def reload_policy(self, new_policy: PolicyConfig) -> None:
        """Hot-reload the privacy policy (e.g. from the dashboard)."""
        self.policy = new_policy
        self._entity_types = [
            et for et in self.policy.entities if et != "DEFAULT"
        ]
        for rec in self.policy.custom_recognizers:
            if rec.entity not in self._entity_types:
                self._entity_types.append(rec.entity)
        # Re-register custom recognizers
        self._register_custom_recognizers()

    async def on_call_tool(self, context, call_next):
        """Intercept tool calls: de-map surrogates in args, mask PII in results."""
        tool_name = getattr(context.message, "name", "")

        # PRE-CALL: replace surrogates in arguments with real values
        message = context.message
        demapped_count = 0
        if message.arguments:
            new_args = self._demap_arguments(message.arguments)
            if new_args != message.arguments:
                demapped_count = self._count_demap_changes(
                    message.arguments, new_args
                )
                context = context.copy(
                    message=type(message)(
                        name=message.name,
                        arguments=new_args,
                    )
                )

        if demapped_count > 0 and self.audit_log is not None:
            self.audit_log.record(AuditEvent(
                tool_name=tool_name,
                direction="demap",
                demapped_count=demapped_count,
            ))

        # Detect sensitive arg patterns BEFORE demap is applied — the
        # demapped real values are what hit the backend, but the
        # decision about whether the response should be treated as a
        # credential blob is based on the original (or demapped) arg
        # values. We use the post-demap args because that's what
        # actually identifies the resource being fetched.
        sensitive_call = self._has_sensitive_args(
            context.message.arguments if context.message else None
        )

        # CALL the actual tool
        result = await call_next(context)

        if sensitive_call:
            # POST-CALL: mask the entire result as one SECRET blob,
            # bypassing field-rule and Presidio analysis. The agent
            # gets one opaque surrogate; demap reverses it on the
            # next outbound tool call.
            masked_result, entity_types, masked_count = self._mask_tool_result_as_secret(
                result
            )
        else:
            # POST-CALL: mask PII in the response
            masked_result, entity_types, masked_count = self._mask_tool_result_with_stats(result)

        if masked_count > 0 and self.audit_log is not None:
            self.audit_log.record(AuditEvent(
                tool_name=tool_name,
                direction="mask",
                entity_types=entity_types,
                masked_count=masked_count,
            ))

        # Append a notice so the LLM knows names in the response are surrogates
        if masked_count > 0 and self.policy.surrogate_notice:
            masked_result = self._append_surrogate_notice(masked_result, entity_types)

        return masked_result

    # ── Sensitive-arg blob masking ────────────────────────────────────────

    def _has_sensitive_args(self, arguments: Any) -> bool:
        """Recursively check whether any string arg matches a
        sensitive_arg_patterns glob. Used to flag tool calls whose
        responses should be treated as opaque credential blobs.
        """
        if not self.policy.sensitive_arg_patterns or arguments is None:
            return False
        patterns = self.policy.sensitive_arg_patterns

        def walk(obj: Any) -> bool:
            if isinstance(obj, str):
                return any(fnmatch.fnmatch(obj, p) for p in patterns)
            if isinstance(obj, dict):
                return any(walk(v) for v in obj.values())
            if isinstance(obj, list):
                return any(walk(v) for v in obj)
            return False

        return walk(arguments)

    def _mask_tool_result_as_secret(
        self, result: Any
    ) -> tuple[Any, list[str], int]:
        """Mask the entire tool result content as one SECRET blob.

        Used when the request matched a sensitive_arg_pattern (e.g.
        Redis cookie payload). Each text content item gets its full
        text replaced with one deterministic SECRET surrogate; demap
        reverses it when the agent passes the surrogate back.
        """
        if result is None:
            return result, [], 0
        masked_count = 0

        def _mask_text_blob(text: str) -> str:
            nonlocal masked_count
            if not text or not text.strip():
                return text
            existing = self.mapping_store.get_surrogate("SECRET", text)
            if existing is not None:
                masked_count += 1
                return existing
            masked = self._mask_field_value(text, "SECRET")
            if masked != text:
                masked_count += 1
            return masked

        # CallToolResult-style object with .content list
        if hasattr(result, "content") and isinstance(result.content, list):
            new_content = []
            for item in result.content:
                if isinstance(item, str):
                    new_content.append(_mask_text_blob(item))
                elif hasattr(item, "text") and isinstance(item.text, str):
                    new_text = _mask_text_blob(item.text)
                    if new_text != item.text:
                        if hasattr(item, "model_copy"):
                            item = item.model_copy(update={"text": new_text})
                        else:
                            try:
                                item.text = new_text
                            except (AttributeError, TypeError):
                                pass
                    new_content.append(item)
                else:
                    new_content.append(item)
            try:
                result.content[:] = new_content
            except (TypeError, AttributeError):
                if hasattr(result, "model_copy"):
                    result = result.model_copy(update={"content": new_content})
            # Wipe structured_content — its fields would otherwise leak the
            # blob contents alongside the masked text.
            if getattr(result, "structured_content", None) is not None:
                try:
                    result.structured_content = None
                except (TypeError, AttributeError):
                    pass
            return result, ["SECRET"] if masked_count > 0 else [], masked_count

        if isinstance(result, str):
            return _mask_text_blob(result), ["SECRET"] if masked_count > 0 else [], masked_count

        if isinstance(result, list):
            new_list = []
            for item in result:
                if isinstance(item, str):
                    new_list.append(_mask_text_blob(item))
                elif hasattr(item, "text") and isinstance(item.text, str):
                    new_text = _mask_text_blob(item.text)
                    if new_text != item.text:
                        if hasattr(item, "model_copy"):
                            item = item.model_copy(update={"text": new_text})
                    new_list.append(item)
                else:
                    new_list.append(item)
            return new_list, ["SECRET"] if masked_count > 0 else [], masked_count

        return result, [], 0

    # ── Surrogate notice ───────────────────────────────────────────────────

    _SURROGATE_NOTICE = "[PII surrogated — pass back verbatim]"

    def _append_surrogate_notice(self, result: Any, entity_types: list[str]) -> Any:
        """Append a short privacy notice to a tool result when PII was masked."""
        notice = TextContent(type="text", text=self._SURROGATE_NOTICE)

        if hasattr(result, "content") and isinstance(result.content, list):
            new_content = list(result.content) + [notice]
            if hasattr(result, "model_copy"):
                return result.model_copy(update={"content": new_content})
        elif isinstance(result, list):
            return list(result) + [notice]
        elif isinstance(result, str):
            return result + "\n\n" + self._SURROGATE_NOTICE

        return result

    # ── Resource read interception ────────────────────────────────────────

    async def on_read_resource(self, context, call_next):
        """Mask PII in resource content."""
        result = await call_next(context)
        return self._mask_resource_result(result)

    # ── Surrogate de-mapping (outbound) ───────────────────────────────────

    def _demap_arguments(
        self, arguments: dict[str, Any], path: str = ""
    ) -> dict[str, Any]:
        """Scan tool arguments for known surrogates and replace with real values.

        Tracks the JSON path so values at paths matching never_mask_paths
        can be skipped — the same path exclusions that protect inbound
        masking also protect outbound demap rewriting (e.g. AWS region
        codes, Logs Insights query strings, technical identifiers).
        """
        new_args: dict[str, Any] = {}
        for key, value in arguments.items():
            child_path = f"{path}.{key}" if path else key
            if self.policy.is_path_excluded(child_path):
                new_args[key] = value
                continue
            if isinstance(value, str):
                new_args[key] = self._demap_string(value)
            elif isinstance(value, dict):
                new_args[key] = self._demap_arguments(value, child_path)
            elif isinstance(value, list):
                new_args[key] = [
                    self._demap_string(v) if isinstance(v, str) else v
                    for v in value
                ]
            else:
                new_args[key] = value
        return new_args

    def _demap_string(self, text: str) -> str:
        """Replace any known surrogates found in a string with their real values.

        Uses case-insensitive matching so that "kari robinson", "KARI ROBINSON",
        and "Kari Robinson" all resolve to the original real value.
        """
        surrogates = self.mapping_store.all_surrogates()
        if not surrogates:
            return text

        # Sort by length descending to match longer surrogates first.
        # Skip very short surrogates (< 4 chars) to avoid matching
        # inside unrelated words (e.g. "Li" inside "application").
        for surrogate in sorted(surrogates, key=len, reverse=True):
            if len(surrogate) < 4:
                continue
            # Case-insensitive search
            idx = text.lower().find(surrogate.lower())
            while idx != -1:
                end = idx + len(surrogate)
                # Word boundary check: don't replace inside larger words
                char_before = text[idx - 1] if idx > 0 else " "
                char_after = text[end] if end < len(text) else " "
                if char_before.isalnum() or char_after.isalnum():
                    idx = text.lower().find(surrogate.lower(), end)
                    continue
                result = self.mapping_store.has_surrogate_anywhere(surrogate)
                if result is not None:
                    _entity_type, real_value = result
                    text = text[:idx] + real_value + text[end:]
                    # Continue searching after the replacement
                    idx = text.lower().find(surrogate.lower(), idx + len(real_value))
                else:
                    break
        return text

    # ── PII masking (inbound) ─────────────────────────────────────────────

    def _mask_tool_result(self, result: Any) -> Any:
        """Mask PII in a tool call result.

        Tool results are typically CallToolResult objects with a .content list,
        or plain strings/lists.
        """
        if result is None:
            return result

        # Handle CallToolResult (the actual type returned by FastMCP proxies)
        if hasattr(result, "content") and isinstance(result.content, list):
            masked = [self._mask_content_item(item) for item in result.content]
            try:
                result.content[:] = masked
            except (TypeError, AttributeError):
                if hasattr(result, "model_copy"):
                    result = result.model_copy(update={"content": masked})
            # Also mask structured_content
            sc = getattr(result, "structured_content", None)
            if sc is not None:
                masked_sc, _, _ = self._mask_json_tree(sc)
                try:
                    result.structured_content = masked_sc
                except (TypeError, AttributeError):
                    pass
            return result

        if isinstance(result, str):
            return self._mask_text(result)
        if isinstance(result, list):
            return [self._mask_content_item(item) for item in result]
        return result

    def _mask_tool_result_with_stats(
        self, result: Any
    ) -> tuple[Any, list[str], int]:
        """Mask PII and return (masked_result, entity_types_found, count)."""
        if result is None:
            return result, [], 0

        # Handle CallToolResult (the actual type returned by FastMCP proxies)
        if hasattr(result, "content") and isinstance(result.content, list):
            masked_content, types, count = self._mask_content_list_with_stats(
                result.content
            )
            if count > 0:
                # Mutate in place: FastMCP may serialize the original object
                # rather than the middleware's return value.
                try:
                    result.content[:] = masked_content
                except (TypeError, AttributeError):
                    if hasattr(result, "model_copy"):
                        result = result.model_copy(update={"content": masked_content})

            # Also mask structured_content — MCP clients may read this
            # instead of the text content field.
            sc = getattr(result, "structured_content", None)
            if sc is not None:
                masked_sc, sc_types, sc_count = self._mask_json_tree(sc)
                types = list(dict.fromkeys(types + sc_types))
                count += sc_count
                try:
                    result.structured_content = masked_sc
                except (TypeError, AttributeError):
                    pass

            return result, types, count

        all_types: list[str] = []
        total_count = 0

        if isinstance(result, str):
            masked, types, count = self._mask_text_with_stats(result)
            return masked, types, count
        if isinstance(result, list):
            masked_items, all_types, total_count = self._mask_content_list_with_stats(
                result
            )
            return masked_items, all_types, total_count
        return result, [], 0

    def _mask_content_list_with_stats(
        self, items: list[Any]
    ) -> tuple[list[Any], list[str], int]:
        """Mask PII in a list of content items, returning (masked_items, entity_types, count)."""
        all_types: list[str] = []
        total_count = 0
        masked_items = []

        for item in items:
            if isinstance(item, str):
                masked, types, count = self._mask_text_with_stats(item)
                masked_items.append(masked)
                all_types.extend(types)
                total_count += count
            elif hasattr(item, "text") and isinstance(item.text, str):
                masked, types, count = self._mask_text_with_stats(item.text)
                if masked != item.text:
                    if hasattr(item, "model_copy"):
                        item = item.model_copy(update={"text": masked})
                    elif hasattr(item, "_replace"):
                        item = item._replace(text=masked)
                    else:
                        try:
                            item.text = masked
                        except (AttributeError, TypeError):
                            pass
                masked_items.append(item)
                all_types.extend(types)
                total_count += count
            else:
                masked_items.append(item)

        # Deduplicate entity types while preserving order
        seen = set()
        unique_types = []
        for t in all_types:
            if t not in seen:
                seen.add(t)
                unique_types.append(t)
        return masked_items, unique_types, total_count

    @staticmethod
    def _count_demap_changes(
        original: dict[str, Any], new: dict[str, Any]
    ) -> int:
        """Count how many string values changed between original and new args."""
        count = 0
        for key in original:
            orig_val = original[key]
            new_val = new.get(key)
            if isinstance(orig_val, str) and isinstance(new_val, str):
                if orig_val != new_val:
                    count += 1
            elif isinstance(orig_val, dict) and isinstance(new_val, dict):
                count += PrivacyMiddleware._count_demap_changes(orig_val, new_val)
            elif isinstance(orig_val, list) and isinstance(new_val, list):
                for o, n in zip(orig_val, new_val):
                    if isinstance(o, str) and isinstance(n, str) and o != n:
                        count += 1
        return count

    def _mask_resource_result(self, result: Any) -> Any:
        """Mask PII in a resource read result."""
        if result is None:
            return result
        if hasattr(result, "contents") and isinstance(result.contents, list):
            masked = [self._mask_content_item(item) for item in result.contents]
            if hasattr(result, "model_copy"):
                return result.model_copy(update={"contents": masked})
            return result
        if isinstance(result, str):
            return self._mask_text(result)
        if isinstance(result, list):
            return [self._mask_content_item(item) for item in result]
        return result

    def _mask_content_item(self, item: Any) -> Any:
        """Mask PII in a single content item (TextContent, etc.)."""
        # Handle mcp TextContent objects
        if hasattr(item, "text") and isinstance(item.text, str):
            masked = self._mask_text(item.text)
            if masked != item.text:
                # Create a copy with masked text
                if hasattr(item, "model_copy"):
                    return item.model_copy(update={"text": masked})
                elif hasattr(item, "_replace"):
                    return item._replace(text=masked)
                # Fallback: try to set directly
                try:
                    item.text = masked
                except (AttributeError, TypeError):
                    pass
            return item
        # Plain string
        if isinstance(item, str):
            return self._mask_text(item)
        return item

    def _mask_text(self, text: str) -> str:
        """Run Presidio analysis + anonymization on a text string."""
        masked, _types, _count = self._mask_text_with_stats(text)
        return masked

    def _apply_field_rules(self, text: str) -> tuple[str, int]:
        """Apply field-level PII rules to JSON text.

        Parses the text as JSON, walks all fields, and masks values whose
        field path matches a rule in the policy. Handles PERSON fields
        specially: if adjacent first_name/last_name fields exist, combines
        them for consistent surrogate generation.

        Returns (masked_text, replacement_count). If the text is not valid
        JSON, returns it unchanged.
        """
        if not self.policy.field_rules:
            return text, 0

        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return text, 0

        count = 0

        def walk(obj: Any, path: str) -> Any:
            nonlocal count
            if isinstance(obj, dict):
                # Look for first_name + last_name pairs to combine
                obj = self._combine_name_fields(obj, path)

                new_obj = {}
                for key, value in obj.items():
                    field_path = f"{path}.{key}" if path else key
                    # Path exclusions take priority over all field rules
                    if self.policy.is_path_excluded(field_path):
                        new_obj[key] = value
                        continue
                    entity = self.policy.match_field(field_path)
                    if entity and isinstance(value, str) and value.strip():
                        # For generic field patterns like *.name, validate
                        # that the value actually looks like the expected
                        # entity type before masking. Specific fields like
                        # *.first_name are trusted without validation.
                        if key == "name" and entity == "PERSON":
                            if not self._looks_like_person_name(value):
                                new_obj[key] = walk(value, field_path)
                                continue
                        # If a SECRET field rule fires on something that
                        # is structurally an email, mask as EMAIL_ADDRESS
                        # instead so the surrogate is email-shaped (not a
                        # password). This matters for 1Password USERNAME
                        # fields whose value is the user's email address.
                        if entity == "SECRET" and self._looks_like_email(value):
                            entity = "EMAIL_ADDRESS"
                        masked = self._mask_field_value(value, entity)
                        if masked != value:
                            count += 1
                        new_obj[key] = masked
                    else:
                        new_obj[key] = walk(value, field_path)
                return new_obj
            elif isinstance(obj, list):
                return [walk(item, path) for item in obj]
            return obj

        masked_data = walk(data, "")
        return json.dumps(masked_data, ensure_ascii=False), count

    def _combine_name_fields(self, obj: dict, path: str) -> dict:
        """If a dict has first_name + last_name, ensure consistent mapping.

        Generates the full-name surrogate first (which creates sub-tokens),
        so individual field masking picks up the aligned sub-tokens.
        """
        first = obj.get("first_name", "")
        last = obj.get("last_name", "")
        if first and last and isinstance(first, str) and isinstance(last, str):
            full_name = f"{first} {last}"
            # Validate that this actually looks like a person name —
            # avoids storing mappings for technical identifiers that
            # happen to be in first_name/last_name fields.
            if not self._looks_like_person_name(full_name):
                return obj
            # Check if we already have a mapping
            existing = self.mapping_store.get_surrogate("PERSON", full_name)
            if existing is None:
                # Generate one — this creates sub-token mappings too
                self._mask_field_value(full_name, "PERSON")
        return obj

    # Characters allowed in person names (letters, spaces, hyphens,
    # apostrophes, periods for initials, and accented unicode).
    _NAME_CHAR_RE = re.compile(r"^[\w\s'\-.]+$", re.UNICODE)

    # Loose email shape (RFC 5321 simplified): one @, at least one dot
    # in the host part, no whitespace.
    _EMAIL_SHAPE_RE = re.compile(r"^\S+@\S+\.\S+$")

    def _looks_like_email(self, value: str) -> bool:
        """Return True if value structurally looks like an email."""
        return bool(self._EMAIL_SHAPE_RE.match(value.strip()))

    def _looks_like_person_name(self, value: str) -> bool:
        """Check whether a string plausibly looks like a person name.

        Used to validate generic ``*.name`` field matches before blindly
        masking them as PERSON. Accepts values that:
          1. Are already in the mapping store (previously confirmed PII), OR
          2. Are detected as PERSON by Presidio at any confidence, OR
          3. Have name-like structure: 2+ Title-Case words, only letters
             / hyphens / apostrophes / periods (no digits, slashes, etc.)

        The structural check is needed because Presidio's NER misses
        non-Anglo names like "Nando Sangenetto".
        """
        value = value.strip()
        if not value or len(value) > 80:
            return False

        # Reject snake_case identifiers (provider_company_id, created_by,
        # etc.). Real person names virtually never contain underscores.
        # This must come before the Presidio check, since Presidio's NER
        # often scores these as PERSON at 0.85 regardless.
        if "_" in value:
            return False

        # Reject values containing digits (codes / IDs)
        if any(c.isdigit() for c in value):
            return False

        # Reject if any word in the value is on the allow list
        allow_set = {v.lower() for v in self.policy.allow_list}
        if any(w.lower() in allow_set for w in value.split()):
            return False

        # Already known PII
        if self.mapping_store.get_surrogate("PERSON", value) is not None:
            return True

        # Ask Presidio (any confidence)
        try:
            results = self.analyzer.analyze(
                text=value, language="en",
                entities=["PERSON"], score_threshold=0.0,
            )
            if results:
                return True
        except Exception:
            pass

        # Structural check: 2+ words, each starts with a capital letter,
        # only allowed name characters (no digits/symbols).
        if not self._NAME_CHAR_RE.match(value):
            return False
        words = value.split()
        if len(words) < 2:
            return False
        for w in words:
            # Strip trailing period (e.g. initials like "J.")
            stripped = w.rstrip(".")
            if not stripped:
                return False
            # Each word must start with an uppercase letter
            if not stripped[0].isupper():
                return False
        return True

    def _mask_field_value(self, value: str, entity_type: str) -> str:
        """Mask a single field value using the configured operator for its entity type."""
        policy = self.policy.get_entity_policy(entity_type)
        op_config = self._policy_to_operator_config(policy, entity_type)
        try:
            result = self.anonymizer.anonymize(
                text=value,
                analyzer_results=[RecognizerResult(
                    entity_type=entity_type,
                    start=0,
                    end=len(value),
                    score=1.0,
                )],
                operators={entity_type: op_config},
            )
            return result.text
        except Exception:
            return value

    def _prescan_known_values(self, text: str) -> tuple[str, int]:
        """Replace any known real PII values with their surrogates.

        Scans the text for all real values in the mapping store (longest-first,
        case-insensitive) and replaces them. This catches:
        - Structured JSON fields (first_name, last_name, email, etc.)
        - Repeat appearances of previously-detected PII
        - Values that Presidio might miss due to lack of surrounding context

        Returns (masked_text, replacement_count).
        """
        count = 0
        forward = self.mapping_store.dump()
        if not forward:
            return text, 0

        # Collect all (real_value, surrogate) pairs across entity types,
        # excluding very short values (< 4 chars) to avoid false matches
        # on common words embedded in longer text.
        # Also skip any values on the policy allow list, and any values
        # whose tokens (split on common separators) match an allow-listed
        # term — catches cascading garbage like "Rebecca Paycom" when
        # "Paycom" is allow-listed, without spuriously skipping values
        # that just happen to contain an allow-listed word as a substring
        # (e.g. "gary@tryfinch.com" contains "finch" but the local part
        # "tryfinch" is a different token).
        allow_set = {v.lower() for v in self.policy.allow_list}
        sep_re = re.compile(r"[\s_\-./@]+")
        pairs: list[tuple[str, str]] = []
        for _etype, mappings in forward.items():
            for real_val, surrogate in mappings.items():
                if len(real_val) < 4:
                    continue
                rv_lower = real_val.lower()
                if rv_lower in allow_set:
                    continue
                tokens = sep_re.split(rv_lower)
                if any(tok in allow_set for tok in tokens if len(tok) >= 3):
                    continue
                pairs.append((real_val, surrogate))

        # Sort by length descending — replace longer values first
        pairs.sort(key=lambda p: len(p[0]), reverse=True)

        # Pre-compute spans to protect from replacement.
        # NOTE: We deliberately do NOT skip URLs here — confirmed PII
        # in the mapping store should be masked even inside URLs (e.g.
        # a real name appearing in a Slack message link). URL exclusion
        # only applies to Presidio NER detections to avoid corrupting
        # domain names like slack.com.
        try:
            json.loads(text)
            json_key_spans = _find_json_key_spans(text)
        except (json.JSONDecodeError, ValueError):
            json_key_spans = []
        uuid_spans = _find_uuid_spans(text)
        slack_id_spans = _find_slack_id_spans(text)
        prefix_id_spans = _find_prefix_id_spans(text)

        for real_val, surrogate in pairs:
            # Case-insensitive search and replace
            idx = text.lower().find(real_val.lower())
            while idx != -1:
                end = idx + len(real_val)
                # Don't replace inside JSON keys
                if json_key_spans and _overlaps_any_span(idx, end, json_key_spans):
                    idx = text.lower().find(real_val.lower(), end)
                    continue
                # Don't replace inside UUIDs
                if uuid_spans and _overlaps_any_span(idx, end, uuid_spans):
                    idx = text.lower().find(real_val.lower(), end)
                    continue
                # Don't replace inside Slack IDs
                if slack_id_spans and _overlaps_any_span(idx, end, slack_id_spans):
                    idx = text.lower().find(real_val.lower(), end)
                    continue
                # Don't replace inside prefix-style IDs (org_*, usr_*, etc.)
                if prefix_id_spans and _overlaps_any_span(idx, end, prefix_id_spans):
                    idx = text.lower().find(real_val.lower(), end)
                    continue
                # Word boundary check: the match must not be embedded
                # inside a larger word (e.g. "wright" inside "playwright").
                char_before = text[idx - 1] if idx > 0 else " "
                char_after = text[end] if end < len(text) else " "
                if char_before.isalnum() or char_after.isalnum():
                    idx = text.lower().find(real_val.lower(), end)
                    continue
                text = text[:idx] + surrogate + text[end:]
                count += 1
                # Recompute key spans since offsets shifted
                if json_key_spans:
                    json_key_spans = _find_json_key_spans(text)
                idx = text.lower().find(real_val.lower(), idx + len(surrogate))

        return text, count

    def _mask_text_with_stats(self, text: str) -> tuple[str, list[str], int]:
        """Run Presidio analysis + anonymization, returning (masked, entity_types, count).

        Two-phase approach:
        1. Pre-scan: replace any known real values from the mapping store
           (catches structured fields like first_name/last_name and repeat
           appearances of previously-detected PII)
        2. Presidio: detect and mask any *new* PII not yet in the store

        For valid JSON input, masking is applied per-value on the parsed tree
        and then re-serialized with json.dumps() to guarantee valid output.
        """
        if not text or not text.strip():
            return text, [], 0

        # First check for partially masked values and reconcile them
        text = self._reconcile_partial_masks(text)

        # Phase 0: Apply field-level rules to JSON responses.
        # This handles structured fields like first_name/last_name
        # that Presidio can't detect without context.
        text, field_count = self._apply_field_rules(text)

        # JSON-safe path: parse, mask individual string values, re-serialize.
        # This prevents surrogates with special characters from corrupting JSON.
        try:
            parsed = json.loads(text)
            if isinstance(parsed, (dict, list)):
                masked_data, json_types, json_count = self._mask_json_tree(parsed)
                total = field_count + json_count
                return json.dumps(masked_data, ensure_ascii=False), json_types, total
        except (json.JSONDecodeError, ValueError):
            pass

        # Non-JSON path: prescan + Presidio on raw text
        return self._mask_plain_text(text, field_count)

    def _mask_json_tree(self, obj: Any, path: str = "") -> tuple[Any, list[str], int]:
        """Walk a parsed JSON tree and mask each string value individually.

        Tracks the JSON path so values at paths matching never_mask_paths
        patterns can be skipped.

        Returns (masked_obj, entity_types, count).
        """
        all_types: set[str] = set()
        total_count = 0

        if isinstance(obj, dict):
            new_obj = {}
            for key, value in obj.items():
                child_path = f"{path}.{key}" if path else key
                if self.policy.is_path_excluded(child_path):
                    new_obj[key] = value
                    continue
                masked_val, types, count = self._mask_json_tree(value, child_path)
                new_obj[key] = masked_val
                all_types.update(types)
                total_count += count
            return new_obj, list(all_types), total_count

        if isinstance(obj, list):
            new_list = []
            for item in obj:
                masked_item, types, count = self._mask_json_tree(item, path)
                new_list.append(masked_item)
                all_types.update(types)
                total_count += count
            return new_list, list(all_types), total_count

        if isinstance(obj, str) and obj.strip():
            masked, types, count = self._mask_plain_text(obj, 0)
            return masked, types, count

        return obj, [], 0

    def _mask_plain_text(
        self, text: str, prior_count: int
    ) -> tuple[str, list[str], int]:
        """Run prescan + Presidio on a plain text string.

        Used for both non-JSON text and individual JSON string values.
        Returns (masked_text, entity_types, total_count).
        """
        # Phase 1: Pre-scan for known real values already in the mapping store.
        text, prescan_count = self._prescan_known_values(text)

        # Build allow list: policy allow_list terms + known surrogates
        # so Presidio skips both user-protected terms and already-masked values
        # Build allow list with both original and lowercase forms,
        # since Presidio's allow_list matching is case-sensitive.
        raw_allow = list(self.policy.allow_list) + list(self.mapping_store.all_surrogates())
        allow_list = list({v for term in raw_allow for v in (term, term.lower())})
        allow_list = allow_list or None

        # If the text looks like HTML, extract plain text for analysis.
        # Use a strict regex requiring a valid HTML tag name (letters/digits/
        # hyphens) followed by whitespace, "/", or ">" — this avoids
        # matching Slack mrkdwn like <mailto:foo@bar.com> or <https://x>
        # whose contents would otherwise be stripped away unexamined.
        is_html = bool(re.search(r"<\/?[a-zA-Z][a-zA-Z0-9-]*[\s/>]", text))
        if is_html:
            plain_text, offset_map = _strip_html(text)
        else:
            plain_text = text
            offset_map = None

        # Phase 2: Detect *new* PII on plain text
        try:
            analyzer_results = self.analyzer.analyze(
                text=plain_text,
                language="en",
                entities=self._entity_types if self._entity_types else None,
                score_threshold=0.4,
                allow_list=allow_list,
            )
        except Exception as e:
            logger.warning("Presidio analysis failed: %s", e)
            accumulated = prior_count + prescan_count
            if accumulated > 0:
                return text, [], accumulated
            return text, [], 0

        # Filter out low-quality detections
        analyzer_results = self._filter_results(analyzer_results, plain_text)

        # Drop detections whose text contains an allow-listed word.
        # Presidio's built-in allow_list only matches exact strings, not
        # partial words (e.g. "Data" won't block "Data Syncs").
        if self.policy.allow_list:
            _allow_words = {v.lower() for v in self.policy.allow_list if len(v) >= 3}
            analyzer_results = [
                r for r in analyzer_results
                if not any(w in _allow_words for w in plain_text[r.start:r.end].lower().split())
            ]

        if not analyzer_results:
            accumulated = prior_count + prescan_count
            if accumulated > 0:
                return text, [], accumulated
            return text, [], 0

        entity_types = list({r.entity_type for r in analyzer_results})
        count = len(analyzer_results) + prior_count + prescan_count

        if is_html and offset_map is not None:
            # Apply masks directly to the original HTML using offset mapping
            masked = self._apply_masks_to_html(text, plain_text, analyzer_results, offset_map)
            return masked, entity_types, count

        # Non-HTML: use Presidio's anonymizer directly
        operators = self._build_operator_configs(analyzer_results)
        try:
            result = self.anonymizer.anonymize(
                text=text,
                analyzer_results=analyzer_results,
                operators=operators,
            )
            return result.text, entity_types, count
        except Exception as e:
            logger.warning("Presidio anonymization failed: %s", e)
            return text, [], 0

    @staticmethod
    def _filter_results(
        results: list[RecognizerResult], text: str
    ) -> list[RecognizerResult]:
        """Filter out low-quality Presidio detections.

        Removes:
        - Entities that overlap with JSON object keys (only values should be masked)
        - PERSON entities that are too short (< 3 chars), single initials
        - PERSON entities that span newlines (likely multi-line blobs)
        - PERSON entities that look like URLs
        - PERSON entities that are common short words (1-2 chars)
        """
        # Pre-compute protected spans
        try:
            json.loads(text)
            json_key_spans = _find_json_key_spans(text)
        except (json.JSONDecodeError, ValueError):
            json_key_spans = []
        url_spans = _find_url_spans(text)
        uuid_spans = _find_uuid_spans(text)
        slack_id_spans = _find_slack_id_spans(text)
        prefix_id_spans = _find_prefix_id_spans(text)

        # NER-based entity types need higher confidence thresholds
        # because the spaCy model frequently tags common English words
        # as entities at low–medium confidence (e.g. "disconnect" → PERSON).
        # Pattern-based entities (PHONE, SSN, CC, EMAIL) are regex-matched
        # and reliable at any score.
        _NER_SCORE_THRESHOLDS = {
            "PERSON": 0.85,
            "LOCATION": 0.7,
            "ORGANIZATION": 0.7,
        }

        filtered = []
        for r in results:
            value = text[r.start:r.end]

            # Skip entities that fall inside JSON keys
            if json_key_spans and _overlaps_any_span(r.start, r.end, json_key_spans):
                continue

            # Skip entities inside URLs
            if url_spans and _overlaps_any_span(r.start, r.end, url_spans):
                continue

            # Skip entities inside UUIDs
            if uuid_spans and _overlaps_any_span(r.start, r.end, uuid_spans):
                continue

            # Skip entities inside Slack IDs
            if slack_id_spans and _overlaps_any_span(r.start, r.end, slack_id_spans):
                continue

            # Skip entities inside prefix-style IDs
            if prefix_id_spans and _overlaps_any_span(r.start, r.end, prefix_id_spans):
                continue

            # Enforce higher score thresholds for NER-based entities
            min_score = _NER_SCORE_THRESHOLDS.get(r.entity_type)
            if min_score and r.score < min_score:
                continue

            # Heuristics applied to ALL NER-based entity types
            # (PERSON, LOCATION, ORGANIZATION) — these often misfire on
            # technical identifiers, snake_case names, and pure-numeric
            # values that look entity-shaped to spaCy.
            if r.entity_type in _NER_SCORE_THRESHOLDS:
                stripped = value.strip()
                # Skip snake_case identifiers (created_by, workflow_name, etc.)
                if "_" in stripped:
                    continue
                # Skip pure-digit values like SQL aggregates (COUNT, SUM)
                # which are sometimes serialized as strings (e.g. BIGINT)
                # and tagged as LOCATION (mistaken for ZIP/address).
                if stripped.replace(".", "").replace(",", "").isdigit():
                    continue

            if r.entity_type == "PERSON":
                # Skip very short values (initials, single chars)
                stripped = value.strip().rstrip(".")
                if len(stripped) < 3:
                    continue
                # Skip values spanning newlines (multi-line blobs)
                if "\n" in value:
                    continue
                # Skip values that look like URLs or contain URL patterns
                if "://" in value or "usepylon.com" in value or "assets." in value:
                    continue
                # Skip values containing @ (emails misdetected as names)
                if "@" in value:
                    continue
                # Skip values containing digits (likely identifiers/codes)
                if any(c.isdigit() for c in value):
                    continue

            if r.entity_type == "PHONE_NUMBER":
                # Skip Unix-timestamp-shaped values. Constrained to
                # the 2017–2049 epoch-seconds range (or its ms
                # equivalent) so that real US phone numbers — which
                # start with a 2-9 area code and produce integers
                # ≥ 2_000_000_000 — are unaffected. Pure-digit values
                # in the timestamp band are virtually always epochs.
                bare = value.strip()
                if bare.isdigit():
                    try:
                        n = int(bare)
                        if len(bare) == 10 and 1_500_000_000 <= n <= 2_500_000_000:
                            continue  # Unix seconds (≈ 2017–2049)
                        if len(bare) == 13 and 1_500_000_000_000 <= n <= 2_500_000_000_000:
                            continue  # Unix milliseconds (≈ 2017–2049)
                    except ValueError:
                        pass

            filtered.append(r)
        return filtered

    def _apply_masks_to_html(
        self,
        html: str,
        plain_text: str,
        analyzer_results: list[RecognizerResult],
        offset_map: list[int],
    ) -> str:
        """Apply PII masks to original HTML using plain-text detection offsets.

        For each detected PII span in the plain text, finds the corresponding
        positions in the original HTML and replaces the real value with its
        surrogate.
        """
        # Sort results by start position descending so replacements don't
        # shift offsets of earlier results
        sorted_results = sorted(analyzer_results, key=lambda r: r.start, reverse=True)

        for result in sorted_results:
            real_value = plain_text[result.start:result.end]
            if not real_value.strip():
                continue

            # Generate the surrogate for this entity
            policy = self.policy.get_entity_policy(result.entity_type)
            op_config = self._policy_to_operator_config(policy, result.entity_type)
            try:
                surrogate = self.anonymizer.anonymize(
                    text=real_value,
                    analyzer_results=[RecognizerResult(
                        entity_type=result.entity_type,
                        start=0,
                        end=len(real_value),
                        score=result.score,
                    )],
                    operators={result.entity_type: op_config},
                ).text
            except Exception:
                continue

            # Map plain-text offsets back to HTML offsets
            html_start = offset_map[result.start]
            html_end = offset_map[result.end - 1] + 1

            # Verify the mapped region contains the expected text (not tags)
            html_fragment = html[html_start:html_end]
            # Strip any tags from the fragment to get the text portion
            fragment_text = re.sub(r"<[^>]+>", "", html_fragment)
            if fragment_text.strip() and real_value in fragment_text:
                # Replace the real value in the HTML fragment, preserving tags
                new_fragment = html_fragment.replace(real_value, surrogate, 1)
                html = html[:html_start] + new_fragment + html[html_end:]

        return html

    def _build_operator_configs(
        self, analyzer_results: list[RecognizerResult]
    ) -> dict[str, OperatorConfig]:
        """Map each detected entity type to its configured operator."""
        configs: dict[str, OperatorConfig] = {}

        entity_types_found = {r.entity_type for r in analyzer_results}

        for entity_type in entity_types_found:
            policy = self.policy.get_entity_policy(entity_type)
            configs[entity_type] = self._policy_to_operator_config(policy, entity_type)

        return configs

    def _policy_to_operator_config(
        self, policy: EntityPolicy, entity_type: str
    ) -> OperatorConfig:
        """Convert a policy entry to a Presidio OperatorConfig."""
        if policy.operator == "fpe":
            return OperatorConfig("fpe", {
                "key": self.fpe_key,
                "tweak": policy.tweak or "CBD09280979564",
                "mapping_store": self.mapping_store,
            })
        elif policy.operator == "deterministic_faker":
            return OperatorConfig("deterministic_faker", {
                "key": self.fpe_key,
                "mapping_store": self.mapping_store,
            })
        elif policy.operator == "replace":
            return OperatorConfig("replace", {
                "new_value": policy.new_value or f"<{entity_type}>",
            })
        else:
            return OperatorConfig("replace", {
                "new_value": f"<{entity_type}>",
            })

    # ── Partial mask reconciliation ───────────────────────────────────────

    # Common partial mask patterns: ***-**-6789, XXXX-XXXX-XXXX-1234
    _PARTIAL_PATTERNS = [
        # SSN partial: ***-**-NNNN or XXX-XX-NNNN
        (r'[\*X]{3}-[\*X]{2}-\d{4}', "US_SSN"),
        # Credit card partial: XXXX-XXXX-XXXX-NNNN
        (r'[\*X]{4}-[\*X]{4}-[\*X]{4}-\d{4}', "CREDIT_CARD"),
        # Phone partial: (***) ***-NNNN
        (r'\([\*X]{3}\)\s*[\*X]{3}-\d{4}', "PHONE_NUMBER"),
    ]

    def _reconcile_partial_masks(self, text: str) -> str:
        """Find partially-masked values in text and replace with their full surrogates."""
        for pattern, entity_type in self._PARTIAL_PATTERNS:
            for match in re.finditer(pattern, text):
                partial = match.group()
                surrogate = self.mapping_store.reconcile_partial(entity_type, partial)
                if surrogate is not None:
                    text = text.replace(partial, surrogate, 1)
        return text
