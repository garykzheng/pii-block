"""Policy configuration loader for the MCP Privacy Proxy.

Reads a YAML file that maps PII entity types to anonymization operators,
optionally defines custom regex-based recognizers, and field-level rules
for masking structured JSON responses.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mapping_store import default_data_dir


def default_policy_path() -> Path:
    """Return the default path for the policy file."""
    return default_data_dir() / "policy.yaml"


@dataclass
class EntityPolicy:
    """How to handle a single PII entity type."""
    operator: str                    # "fpe", "deterministic_faker", "replace"
    tweak: str | None = None         # FPE tweak (hex), only for operator=fpe
    new_value: str | None = None     # Replacement text, only for operator=replace


@dataclass
class CustomRecognizer:
    """A regex-based recognizer for domain-specific PII patterns."""
    entity: str           # Entity type name, e.g. "EMPLOYEE_ID"
    pattern: str          # Regex pattern
    score: float = 0.85   # Confidence score to assign
    operator: str = "fpe"
    tweak: str | None = None


@dataclass
class FieldRule:
    """A rule that maps a JSON field path pattern to a PII entity type.

    The pattern uses glob syntax matched against dot-separated JSON paths.
    Examples: "*.first_name", "data.*.email", "*.ssn"
    """
    pattern: str          # Glob pattern for JSON field paths
    entity: str           # Entity type, e.g. "PERSON", "EMAIL_ADDRESS"


@dataclass
class PolicyConfig:
    """Full proxy policy configuration."""
    entities: dict[str, EntityPolicy] = field(default_factory=dict)
    custom_recognizers: list[CustomRecognizer] = field(default_factory=list)
    field_rules: list[FieldRule] = field(default_factory=list)
    allow_list: list[str] = field(default_factory=list)
    surrogate_notice: bool = True

    def get_entity_policy(self, entity_type: str) -> EntityPolicy:
        """Return the policy for a given entity type, falling back to DEFAULT."""
        if entity_type in self.entities:
            return self.entities[entity_type]
        return self.entities.get(
            "DEFAULT",
            EntityPolicy(operator="replace", new_value="<REDACTED>"),
        )

    def match_field(self, field_path: str) -> str | None:
        """Return the entity type for a field path, or None if no rule matches."""
        for rule in self.field_rules:
            if fnmatch.fnmatch(field_path, rule.pattern):
                return rule.entity
        return None


def load_policy(path: str | Path) -> PolicyConfig:
    """Load a PolicyConfig from a YAML file."""
    path = Path(path)
    with path.open() as f:
        raw: dict[str, Any] = yaml.safe_load(f)

    entities: dict[str, EntityPolicy] = {}
    for name, cfg in raw.get("entities", {}).items():
        entities[name] = EntityPolicy(
            operator=cfg.get("operator", "replace"),
            tweak=cfg.get("tweak"),
            new_value=cfg.get("new_value"),
        )

    custom_recognizers: list[CustomRecognizer] = []
    for rec in raw.get("custom_recognizers", []):
        custom_recognizers.append(CustomRecognizer(
            entity=rec["entity"],
            pattern=rec["pattern"],
            score=rec.get("score", 0.85),
            operator=rec.get("operator", "fpe"),
            tweak=rec.get("tweak"),
        ))

    field_rules: list[FieldRule] = []
    for rule in raw.get("field_rules", []):
        field_rules.append(FieldRule(
            pattern=rule["pattern"],
            entity=rule["entity"],
        ))

    allow_list: list[str] = raw.get("allow_list", [])
    surrogate_notice: bool = raw.get("surrogate_notice", True)

    return PolicyConfig(
        entities=entities,
        custom_recognizers=custom_recognizers,
        field_rules=field_rules,
        allow_list=allow_list,
        surrogate_notice=surrogate_notice,
    )


def save_policy(policy: PolicyConfig, path: str | Path) -> None:
    """Serialize a PolicyConfig back to a YAML file."""
    path = Path(path)
    data: dict[str, Any] = {}

    if policy.entities:
        entities_data: dict[str, dict[str, Any]] = {}
        for name, ep in policy.entities.items():
            entry: dict[str, Any] = {"operator": ep.operator}
            if ep.tweak is not None:
                entry["tweak"] = ep.tweak
            if ep.new_value is not None:
                entry["new_value"] = ep.new_value
            entities_data[name] = entry
        data["entities"] = entities_data

    if policy.custom_recognizers:
        recs: list[dict[str, Any]] = []
        for rec in policy.custom_recognizers:
            entry = {
                "entity": rec.entity,
                "pattern": rec.pattern,
                "score": rec.score,
                "operator": rec.operator,
            }
            if rec.tweak is not None:
                entry["tweak"] = rec.tweak
            recs.append(entry)
        data["custom_recognizers"] = recs

    if policy.field_rules:
        rules: list[dict[str, str]] = []
        for rule in policy.field_rules:
            rules.append({
                "pattern": rule.pattern,
                "entity": rule.entity,
            })
        data["field_rules"] = rules

    if policy.allow_list:
        data["allow_list"] = policy.allow_list

    if not policy.surrogate_notice:
        data["surrogate_notice"] = False

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
