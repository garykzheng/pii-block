"""Policy configuration loader for the MCP Privacy Proxy.

Reads a YAML file that maps PII entity types to anonymization operators and
optionally defines custom regex-based recognizers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


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
class PolicyConfig:
    """Full proxy policy configuration."""
    entities: dict[str, EntityPolicy] = field(default_factory=dict)
    custom_recognizers: list[CustomRecognizer] = field(default_factory=list)

    def get_entity_policy(self, entity_type: str) -> EntityPolicy:
        """Return the policy for a given entity type, falling back to DEFAULT."""
        if entity_type in self.entities:
            return self.entities[entity_type]
        return self.entities.get(
            "DEFAULT",
            EntityPolicy(operator="replace", new_value="<REDACTED>"),
        )


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

    return PolicyConfig(entities=entities, custom_recognizers=custom_recognizers)


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

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
