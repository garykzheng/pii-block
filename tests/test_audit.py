"""Tests for AuditLog: recording, stats, serialization."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from audit import AuditLog, AuditEvent


class TestAuditLogBasic:
    """Basic recording and retrieval."""

    def test_record_and_recent(self):
        log = AuditLog()
        log.record(AuditEvent(tool_name="get_user", direction="mask", entity_types=["PERSON"], masked_count=1))
        log.record(AuditEvent(tool_name="search", direction="demap", demapped_count=2))

        assert len(log) == 2
        recent = log.recent(10)
        assert len(recent) == 2
        # Most recent first
        assert recent[0].tool_name == "search"
        assert recent[1].tool_name == "get_user"

    def test_recent_limit(self):
        log = AuditLog()
        for i in range(20):
            log.record(AuditEvent(tool_name=f"tool_{i}"))

        recent = log.recent(5)
        assert len(recent) == 5
        assert recent[0].tool_name == "tool_19"

    def test_ring_buffer_overflow(self):
        log = AuditLog(maxlen=5)
        for i in range(10):
            log.record(AuditEvent(tool_name=f"tool_{i}"))

        assert len(log) == 5
        recent = log.recent(10)
        assert len(recent) == 5
        assert recent[0].tool_name == "tool_9"
        assert recent[4].tool_name == "tool_5"

    def test_empty_log(self):
        log = AuditLog()
        assert len(log) == 0
        assert log.recent(10) == []


class TestAuditStats:
    """Statistics computation."""

    def test_stats_basic(self):
        log = AuditLog()
        log.record(AuditEvent(
            server="fs", tool_name="read_file", direction="mask",
            entity_types=["US_SSN", "PERSON"], masked_count=3,
        ))
        log.record(AuditEvent(
            server="fs", tool_name="write_file", direction="demap",
            entity_types=[], demapped_count=1,
        ))
        log.record(AuditEvent(
            server="github", tool_name="search", direction="mask",
            entity_types=["PERSON"], masked_count=2,
        ))

        stats = log.stats()
        assert stats["total_events"] == 3
        assert stats["total_masked"] == 5
        assert stats["total_demapped"] == 1
        assert stats["entity_type_counts"]["PERSON"] == 2
        assert stats["entity_type_counts"]["US_SSN"] == 1
        assert stats["tool_counts"]["read_file"] == 1
        assert stats["tool_counts"]["search"] == 1
        assert stats["server_counts"]["fs"] == 2
        assert stats["server_counts"]["github"] == 1

    def test_stats_empty(self):
        log = AuditLog()
        stats = log.stats()
        assert stats["total_events"] == 0
        assert stats["total_masked"] == 0
        assert stats["entity_type_counts"] == {}


class TestAuditSerialization:
    """JSON serialization."""

    def test_to_json(self):
        log = AuditLog()
        log.record(AuditEvent(
            tool_name="get_user", direction="mask",
            entity_types=["PERSON"], masked_count=1,
        ))

        data = log.to_json()
        assert len(data) == 1
        assert data[0]["tool_name"] == "get_user"
        assert data[0]["entity_types"] == ["PERSON"]
        assert data[0]["masked_count"] == 1

    def test_to_json_empty(self):
        log = AuditLog()
        assert log.to_json() == []
