"""Bidirectional mapping store for PII surrogates.

Maintains real_value <-> surrogate mappings keyed by entity type,
with encrypted file persistence, file-level locking for cross-process safety,
and partial-mask reconciliation.

Encryption: mappings are AES-256-GCM encrypted at rest. The encryption key is
stored in the OS keyring (macOS Keychain, Windows Credential Locker, Linux
Secret Service) via the `keyring` library.

Multiple proxy processes can share the same mappings file safely.
Reads check the file mtime and refresh when another process has written.
Writes use fcntl file locking to prevent corruption.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import logging
import os
import platform
import re
import secrets
from pathlib import Path
from typing import Any

import keyring
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("mapping_store")

_KEYRING_SERVICE = "mcp-privacy-proxy"
_KEYRING_ACCOUNT = "mappings-key"


# ── Encryption helpers ───────────────────────────────────────────────────

def _get_or_create_key() -> bytes:
    """Retrieve the AES key from the OS keyring, creating one if needed."""
    stored = keyring.get_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT)
    if stored is not None:
        return bytes.fromhex(stored)

    key = secrets.token_bytes(32)
    keyring.set_password(_KEYRING_SERVICE, _KEYRING_ACCOUNT, key.hex())
    return key


def _encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce (12 bytes) + ciphertext + tag (16 bytes)."""
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM. Expects nonce (12 bytes) + ciphertext + tag."""
    return AESGCM(key).decrypt(data[:12], data[12:], None)


# ── Path helpers ─────────────────────────────────────────────────────────

def default_data_dir() -> Path:
    """Return the platform-appropriate data directory for the proxy.

    macOS:  ~/Library/Application Support/mcp-privacy-proxy/
    Linux:  ~/.local/share/mcp-privacy-proxy/
    """
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "mcp-privacy-proxy"
    return Path.home() / ".local" / "share" / "mcp-privacy-proxy"


def default_mapping_path() -> Path:
    """Return the default path for the shared mappings file."""
    return default_data_dir() / "mappings.json"


# ── MappingStore ─────────────────────────────────────────────────────────

class MappingStore:
    """Bidirectional mapping between real PII values and surrogates.

    Supports cross-process sharing via file locking and mtime-based refresh.
    Encrypts the mappings file at rest using a key stored in the OS keyring.
    """

    # Entity types where sub-token mappings should be created
    _SUBTOKENIZE_TYPES = {"PERSON"}

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        # { entity_type: { real_value: surrogate } }
        self._forward: dict[str, dict[str, str]] = {}
        # { entity_type: { surrogate: real_value } }
        self._reverse: dict[str, dict[str, str]] = {}
        # Case-insensitive reverse: { entity_type: { surrogate_lower: (surrogate, real_value) } }
        self._reverse_ci: dict[str, dict[str, tuple[str, str]]] = {}
        self._lock = asyncio.Lock()
        self._last_mtime: float = 0.0
        self._enc_key: bytes = _get_or_create_key()

        if self._path and self._path.exists():
            self._load_sync()

    # ── Cross-process file coordination ───────────────────────────────────

    def _maybe_refresh(self) -> None:
        """Re-read from disk if another process has updated the file."""
        if not self._path or not self._path.exists():
            return
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            return
        if mtime != self._last_mtime:
            self._load_sync()

    def _write_locked(self) -> None:
        """Write encrypted mappings to disk atomically.

        Uses a write-to-temp + os.rename strategy so that concurrent
        readers in other processes never see a partial / truncated /
        being-written file. POSIX rename is atomic at the filesystem
        level: a reader either gets the old file in full or the new
        file in full, never an in-progress write. Without this, the
        previous flow (open(wb) truncates → acquire lock → write) had
        a window where a reader could open the truncated empty file,
        fail to decrypt, silently keep its stale in-memory state, and
        miss surrogates that another process had just stored. That
        manifested as e.g. Playwright failing to demap a credential
        right after the proxy that issued it stored the mapping.
        """
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)

        json_bytes = json.dumps({"forward": self._forward}, indent=2).encode()
        encrypted = _encrypt(json_bytes, self._enc_key)

        # Write to a sibling temp file first; lock it for any concurrent
        # writers using the same temp name (best-effort), then rename.
        tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
        fd = None
        try:
            fd = open(tmp_path, "wb")
            fcntl.flock(fd, fcntl.LOCK_EX)
            fd.write(encrypted)
            fd.flush()
            os.fsync(fd.fileno())
        finally:
            if fd is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
                fd.close()

        os.chmod(tmp_path, 0o600)
        os.rename(tmp_path, self._path)
        self._last_mtime = self._path.stat().st_mtime

    # ── Public API ────────────────────────────────────────────────────────

    def get_surrogate(self, entity_type: str, real_value: str) -> str | None:
        """Look up the surrogate for a real value (case-insensitive)."""
        self._maybe_refresh()
        # Exact match first
        fwd = self._forward.get(entity_type, {})
        if real_value in fwd:
            return fwd[real_value]
        # Case-insensitive fallback
        real_lower = real_value.lower()
        for rv, surr in fwd.items():
            if rv.lower() == real_lower:
                return surr
        return None

    def get_real_value(self, entity_type: str, surrogate: str) -> str | None:
        """Look up the real value for a surrogate (or None)."""
        self._maybe_refresh()
        return self._reverse.get(entity_type, {}).get(surrogate)

    def store(self, entity_type: str, real_value: str, surrogate: str) -> None:
        """Store a bidirectional mapping and persist to disk.

        For PERSON entities with multiple words, also stores aligned sub-token
        mappings (e.g., "Peter" → "Kari", "Swenty" → "Robinson") so that
        split first/last name fields and case variations resolve correctly.
        """
        self._maybe_refresh()
        self._store_single(entity_type, real_value, surrogate)

        # Create sub-token mappings for multi-word entities like PERSON
        if entity_type in self._SUBTOKENIZE_TYPES:
            real_parts = real_value.split()
            surr_parts = surrogate.split()
            if len(real_parts) > 1 and len(real_parts) == len(surr_parts):
                for rp, sp in zip(real_parts, surr_parts):
                    if rp == real_value:  # Don't re-store the full value
                        continue
                    # Only create sub-token if no mapping exists yet —
                    # first full-name encounter wins for sub-tokens.
                    if self._forward.get(entity_type, {}).get(rp) is not None:
                        continue
                    # Reverse-direction collision check: if this surrogate
                    # token is already used for a different real value,
                    # skip creating the sub-token. Otherwise demap would
                    # ambiguously resolve back to the wrong real value.
                    rev_existing = self._reverse.get(entity_type, {}).get(sp)
                    if rev_existing is not None and rev_existing != rp:
                        continue
                    self._store_single(entity_type, rp, sp)

        self._write_locked()

    def _store_single(self, entity_type: str, real_value: str, surrogate: str) -> None:
        """Store one mapping in the forward, reverse, and case-insensitive indexes."""
        self._forward.setdefault(entity_type, {})[real_value] = surrogate
        self._reverse.setdefault(entity_type, {})[surrogate] = real_value
        self._reverse_ci.setdefault(entity_type, {})[surrogate.lower()] = (surrogate, real_value)

    def has_surrogate_anywhere(self, surrogate: str) -> tuple[str, str] | None:
        """Search all entity types for a surrogate (case-insensitive).

        Returns (entity_type, real_value) or None.
        """
        self._maybe_refresh()
        # Exact match first
        for entity_type, rev in self._reverse.items():
            if surrogate in rev:
                return entity_type, rev[surrogate]
        # Case-insensitive fallback
        surr_lower = surrogate.lower()
        for entity_type, rev_ci in self._reverse_ci.items():
            if surr_lower in rev_ci:
                _canonical_surr, real_value = rev_ci[surr_lower]
                return entity_type, real_value
        return None

    def reconcile_partial(
        self, entity_type: str, partial_value: str
    ) -> str | None:
        """Try to match a partially-masked value (e.g. '***-**-6789') to an existing mapping.

        Returns the surrogate if a unique match is found, None otherwise.
        """
        self._maybe_refresh()
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
        self._maybe_refresh()
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
            self._write_locked()

    def _save_sync(self) -> None:
        self._write_locked()

    def _load_sync(self) -> None:
        if not self._path or not self._path.exists():
            return

        raw = self._path.read_bytes()
        if not raw:
            return

        json_bytes = _decrypt(raw, self._enc_key)
        data = json.loads(json_bytes)

        self._forward = data.get("forward", {})
        self._reverse = {}
        self._reverse_ci = {}
        for etype, fwd in self._forward.items():
            self._reverse[etype] = {v: k for k, v in fwd.items()}
            self._reverse_ci[etype] = {
                v.lower(): (v, k) for k, v in fwd.items()
            }
        self._last_mtime = self._path.stat().st_mtime

    async def load(self) -> None:
        """Reload mappings from disk (async-safe)."""
        async with self._lock:
            self._load_sync()

    # ── Introspection ─────────────────────────────────────────────────────

    def all_surrogates(self) -> set[str]:
        """Return the set of all known surrogate values across all entity types."""
        self._maybe_refresh()
        result: set[str] = set()
        for rev in self._reverse.values():
            result.update(rev.keys())
        return result

    def dump(self) -> dict[str, Any]:
        """Return a serializable snapshot of forward mappings."""
        self._maybe_refresh()
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
