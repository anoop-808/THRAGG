"""
core.attack_chain_rule
======================

Declarative rules for turning correlations into attack chains.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..correlation.correlation import Correlation

__all__ = ["AttackChainRule", "AttackChainRuleRepository"]


@dataclass(frozen=True)
class AttackChainRule:
    """Rule metadata and matching constraints for one attack narrative type."""

    rule_id: str
    title: str
    description: str
    min_correlations: int = 2
    min_distinct_entities: int = 2
    stage_sequence: tuple[str, ...] = ()
    required_tags: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackChainRule":
        """Build one rule from JSON/YAML-like plain data."""
        return cls(
            rule_id=str(data["rule_id"]),
            title=str(data["title"]),
            description=str(data["description"]),
            min_correlations=int(data.get("min_correlations", 2)),
            min_distinct_entities=int(data.get("min_distinct_entities", 2)),
            stage_sequence=tuple(str(item) for item in data.get("stage_sequence", ())),
            required_tags=tuple(str(item) for item in data.get("required_tags", ())),
            mitre_techniques=tuple(
                str(item) for item in data.get("mitre_techniques", ())
            ),
        )

    def matches(self, correlations: tuple[Correlation, ...]) -> bool:
        """Return True when a connected component satisfies this rule."""
        if len(correlations) < self.min_correlations:
            return False
        entity_ids = {
            str(entity["id"])
            for correlation in correlations
            for entity in correlation.matched_entities
            if "id" in entity
        }
        if len(entity_ids) < self.min_distinct_entities:
            return False
        tags = {tag for correlation in correlations for tag in correlation.tags}
        if not set(self.required_tags).issubset(tags):
            return False
        stages = tuple(
            str(correlation.correlation_explanation.get("stage", "DISCOVERY"))
            for correlation in correlations
        )
        return not self.stage_sequence or _is_subsequence(self.stage_sequence, stages)


class AttackChainRuleRepository:
    """Load attack-chain rules without changing engine code."""

    def __init__(self, rules: tuple[AttackChainRule, ...] | None = None) -> None:
        self._rules = rules or self.from_json(
            Path(__file__).with_name("attack_chain_rules.json")
        )

    def list(self) -> tuple[AttackChainRule, ...]:
        """Return rules in deterministic order."""
        return tuple(sorted(self._rules, key=lambda rule: rule.rule_id))

    @staticmethod
    def from_json(path: Path) -> tuple[AttackChainRule, ...]:
        """Load rules from a JSON file."""
        data = json.loads(path.read_text(encoding="utf-8"))
        return tuple(AttackChainRule.from_dict(item) for item in data["rules"])


def _is_subsequence(needle: tuple[str, ...], haystack: tuple[str, ...]) -> bool:
    remaining = iter(haystack)
    return all(item in remaining for item in needle)
