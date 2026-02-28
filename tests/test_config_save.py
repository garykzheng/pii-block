"""Tests for save_policy: round-trip serialization of PolicyConfig."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import PolicyConfig, EntityPolicy, CustomRecognizer, load_policy, save_policy


class TestSavePolicyRoundTrip:
    """save_policy -> load_policy should preserve all fields."""

    def test_basic_round_trip(self, tmp_path):
        path = tmp_path / "policy.yaml"
        original = PolicyConfig(
            entities={
                "US_SSN": EntityPolicy(operator="fpe", tweak="CBD09280979564"),
                "PERSON": EntityPolicy(operator="deterministic_faker"),
                "DEFAULT": EntityPolicy(operator="replace", new_value="<REDACTED>"),
            },
        )

        save_policy(original, path)
        loaded = load_policy(path)

        assert loaded.entities["US_SSN"].operator == "fpe"
        assert loaded.entities["US_SSN"].tweak == "CBD09280979564"
        assert loaded.entities["PERSON"].operator == "deterministic_faker"
        assert loaded.entities["DEFAULT"].operator == "replace"
        assert loaded.entities["DEFAULT"].new_value == "<REDACTED>"

    def test_custom_recognizers_round_trip(self, tmp_path):
        path = tmp_path / "policy.yaml"
        original = PolicyConfig(
            entities={"DEFAULT": EntityPolicy(operator="replace")},
            custom_recognizers=[
                CustomRecognizer(
                    entity="EMPLOYEE_ID",
                    pattern="EMP-\\d{6}",
                    score=0.9,
                    operator="fpe",
                    tweak="AABBCCDD",
                ),
            ],
        )

        save_policy(original, path)
        loaded = load_policy(path)

        assert len(loaded.custom_recognizers) == 1
        rec = loaded.custom_recognizers[0]
        assert rec.entity == "EMPLOYEE_ID"
        assert rec.pattern == "EMP-\\d{6}"
        assert rec.score == 0.9
        assert rec.operator == "fpe"
        assert rec.tweak == "AABBCCDD"

    def test_produces_valid_yaml(self, tmp_path):
        path = tmp_path / "policy.yaml"
        save_policy(
            PolicyConfig(entities={"PERSON": EntityPolicy(operator="replace", new_value="<NAME>")}),
            path,
        )

        data = yaml.safe_load(path.read_text())
        assert "entities" in data
        assert data["entities"]["PERSON"]["operator"] == "replace"
        assert data["entities"]["PERSON"]["new_value"] == "<NAME>"

    def test_empty_policy(self, tmp_path):
        path = tmp_path / "policy.yaml"
        save_policy(PolicyConfig(), path)

        loaded = load_policy(path)
        assert loaded.entities == {}
        assert loaded.custom_recognizers == []

    def test_save_creates_parent_dirs(self, tmp_path):
        path = tmp_path / "sub" / "dir" / "policy.yaml"
        save_policy(
            PolicyConfig(entities={"X": EntityPolicy(operator="replace")}),
            path,
        )
        assert path.exists()
