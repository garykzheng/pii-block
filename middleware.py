"""FastMCP Middleware that intercepts tool calls and resources to mask/unmask PII.

PrivacyMiddleware sits in the proxy pipeline and:
  PRE-CALL:  scans tool arguments for known surrogates, replaces with real values
  POST-CALL: detects PII in results, replaces with deterministic surrogates
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Sequence

from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, RecognizerResult

from fastmcp.server.middleware import Middleware, MiddlewareContext

from audit import AuditLog, AuditEvent
from config import PolicyConfig, EntityPolicy
from mapping_store import MappingStore
from operators import (
    FPEAnonymizer,
    DeterministicFakerAnonymizer,
)

logger = logging.getLogger("privacy_middleware")


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

        # CALL the actual tool
        result = await call_next(context)

        # POST-CALL: mask PII in the response
        masked_result, entity_types, masked_count = self._mask_tool_result_with_stats(result)

        if masked_count > 0 and self.audit_log is not None:
            self.audit_log.record(AuditEvent(
                tool_name=tool_name,
                direction="mask",
                entity_types=entity_types,
                masked_count=masked_count,
            ))

        return masked_result

    # ── Resource read interception ────────────────────────────────────────

    async def on_read_resource(self, context, call_next):
        """Mask PII in resource content."""
        result = await call_next(context)
        return self._mask_resource_result(result)

    # ── Surrogate de-mapping (outbound) ───────────────────────────────────

    def _demap_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Scan tool arguments for known surrogates and replace with real values."""
        new_args: dict[str, Any] = {}
        for key, value in arguments.items():
            if isinstance(value, str):
                new_args[key] = self._demap_string(value)
            elif isinstance(value, dict):
                new_args[key] = self._demap_arguments(value)
            elif isinstance(value, list):
                new_args[key] = [
                    self._demap_string(v) if isinstance(v, str) else v
                    for v in value
                ]
            else:
                new_args[key] = value
        return new_args

    def _demap_string(self, text: str) -> str:
        """Replace any known surrogates found in a string with their real values."""
        surrogates = self.mapping_store.all_surrogates()
        if not surrogates:
            return text

        # Sort by length descending to match longer surrogates first
        for surrogate in sorted(surrogates, key=len, reverse=True):
            if surrogate in text:
                result = self.mapping_store.has_surrogate_anywhere(surrogate)
                if result is not None:
                    _entity_type, real_value = result
                    text = text.replace(surrogate, real_value)
        return text

    # ── PII masking (inbound) ─────────────────────────────────────────────

    def _mask_tool_result(self, result: Any) -> Any:
        """Mask PII in a tool call result.

        Tool results are typically a list of content items. Each text content
        item gets scanned and anonymized.
        """
        if result is None:
            return result

        # FastMCP tool results can be strings, lists of content objects, etc.
        if isinstance(result, str):
            return self._mask_text(result)
        if isinstance(result, list):
            return [self._mask_content_item(item) for item in result]
        # If it's some other type, try to handle it gracefully
        return result

    def _mask_tool_result_with_stats(
        self, result: Any
    ) -> tuple[Any, list[str], int]:
        """Mask PII and return (masked_result, entity_types_found, count)."""
        if result is None:
            return result, [], 0

        all_types: list[str] = []
        total_count = 0

        if isinstance(result, str):
            masked, types, count = self._mask_text_with_stats(result)
            return masked, types, count
        if isinstance(result, list):
            masked_items = []
            for item in result:
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
        return result, [], 0

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

    def _mask_text_with_stats(self, text: str) -> tuple[str, list[str], int]:
        """Run Presidio analysis + anonymization, returning (masked, entity_types, count)."""
        if not text or not text.strip():
            return text, [], 0

        # First check for partially masked values and reconcile them
        text = self._reconcile_partial_masks(text)

        # Build allow list from known surrogates so Presidio doesn't
        # re-detect surrogate values as new PII
        allow_list = list(self.mapping_store.all_surrogates()) or None

        # Detect PII
        try:
            analyzer_results = self.analyzer.analyze(
                text=text,
                language="en",
                entities=self._entity_types if self._entity_types else None,
                score_threshold=0.4,
                allow_list=allow_list,
            )
        except Exception as e:
            logger.warning("Presidio analysis failed: %s", e)
            return text, [], 0

        if not analyzer_results:
            return text, [], 0

        entity_types = list({r.entity_type for r in analyzer_results})
        count = len(analyzer_results)

        # Build operator configs for each entity type found
        operators = self._build_operator_configs(analyzer_results)

        # Anonymize
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
