"""Bidirectional mapping store for PII surrogates.

Maintains real_value <-> surrogate mappings keyed by entity type,
with JSON file persistence and partial-mask reconciliation.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any


class MappingStore:
    """Thread-safe bidirectional mapping between real PII values and surrogates."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        # { entity_type: { real_value: surrogate } }
        self._forward: dict[str, dict[str, str]] = {}
        # { entity_type: { surrogate: real_value } }
        self._reverse: dict[str, dict[str, str]] = {}
        self._lock = asyncio.Lock()

        if self._path and self._path.exists():
            self._load_sync()

    # ── Public API ────────────────────────────────────────────────────────

    def get_surrogate(self, entity_type: str, real_value: str) -> str | None:
        """Look up the surrogate for a real value (or None)."""
        return self._forward.get(entity_type, {}).get(real_value)

    def get_real_value(self, entity_type: str, surrogate: str) -> str | None:
        """Look up the real value for a surrogate (or None)."""
        return self._reverse.get(entity_type, {}).get(surrogate)

    def store(self, entity_type: str, real_value: str, surrogate: str) -> None:
        """Store a bidirectional mapping."""
        self._forward.setdefault(entity_type, {})[real_value] = surrogate
        self._reverse.setdefault(entity_type, {})[surrogate] = real_value

    def has_surrogate_anywhere(self, surrogate: str) -> tuple[str, str] | None:
        """Search all entity types for a surrogate. Returns (entity_type, real_value) or None."""
        for entity_type, rev in self._reverse.items():
            if surrogate in rev:
                return entity_type, rev[surrogate]
        return None

    def reconcile_partial(
        self, entity_type: str, partial_value: str
    ) -> str | None:
        """Try to match a partially-masked value (e.g. '***-**-6789') to an existing mapping.

        Returns the surrogate if a unique match is found, None otherwise.
        """
        # Build a regex from the partial: replace each mask char with .
        # We treat *, X, and x as mask characters when they appear in runs
        pattern = _partial_to_regex(partial_value)
        if pattern is None:
            return None

        matches: list[tuple[str, str]] = []
        for real_val, surrogate in self._forward.get(entity_type, {}).items():
            if re.fullmatch(pattern, real_val):
                matches.append((real_val, surrogate))

        if len(matches) == 1:
            return matches[0][1]
        return None

    def demask_text(self, text: str) -> tuple[str, list[dict[str, str]]]:
        """Replace surrogates in text with real values (longest-first).

        Returns (demasked_text, replacements) where each replacement is
        {"surrogate": ..., "real_value": ..., "entity_type": ...}.
        """
        replacements: list[dict[str, str]] = []
        surrogates = self.all_surrogates()
        if not surrogates:
            return text, replacements

        # Sort by length descending so longer surrogates match first
        for surrogate in sorted(surrogates, key=len, reverse=True):
            if surrogate in text:
                result = self.has_surrogate_anywhere(surrogate)
                if result is not None:
                    entity_type, real_value = result
                    text = text.replace(surrogate, real_value)
                    replacements.append({
                        "surrogate": surrogate,
                        "real_value": real_value,
                        "entity_type": entity_type,
                    })

        return text, replacements

    # ── Persistence ───────────────────────────────────────────────────────

    async def save(self) -> None:
        """Persist mappings to JSON file (async-safe)."""
        if not self._path:
            return
        async with self._lock:
            self._save_sync()

    def _save_sync(self) -> None:
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {"forward": self._forward}
        self._path.write_text(json.dumps(data, indent=2))

    def _load_sync(self) -> None:
        if not self._path or not self._path.exists():
            return
        data = json.loads(self._path.read_text())
        self._forward = data.get("forward", {})
        # Rebuild reverse index
        self._reverse = {}
        for etype, fwd in self._forward.items():
            self._reverse[etype] = {v: k for k, v in fwd.items()}

    async def load(self) -> None:
        """Reload mappings from disk (async-safe)."""
        async with self._lock:
            self._load_sync()

    # ── Introspection ─────────────────────────────────────────────────────

    def all_surrogates(self) -> set[str]:
        """Return the set of all known surrogate values across all entity types."""
        result: set[str] = set()
        for rev in self._reverse.values():
            result.update(rev.keys())
        return result

    def dump(self) -> dict[str, Any]:
        """Return a serializable snapshot of forward mappings."""
        return dict(self._forward)


def _partial_to_regex(partial: str) -> str | None:
    """Convert a partially-masked string to a regex pattern.

    Mask characters (*, X) become '.' wildcards; literal chars are escaped.
    Returns None if the string has no mask characters (nothing to reconcile).
    """
    mask_chars = {"*", "X"}
    has_mask = any(c in mask_chars for c in partial)
    if not has_mask:
        return None

    parts: list[str] = []
    for ch in partial:
        if ch in mask_chars:
            parts.append(".")
        else:
            parts.append(re.escape(ch))
    return "".join(parts)
