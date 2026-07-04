"""
core.correlation_builder
========================

Construction-only builder for Correlation objects.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .correlation import Correlation
from .correlation_rule import CorrelationRule
from .pattern_evaluator import PatternMatch
from .stable_id import stable_sha_id

__all__ = ["CorrelationBuilder", "stable_correlation_id"]


def stable_correlation_id(rule_id: str, entity_ids: tuple[str, ...]) -> str:
    """Return a deterministic correlation id for a rule/entity match."""
    return stable_sha_id("corr", rule_id, *sorted(entity_ids))


class CorrelationBuilder:
    """Build Correlation objects from successful pattern matches."""

    def build(self, rule: CorrelationRule, match: PatternMatch) -> Correlation:
        """Construct one Correlation. No evaluation or validation happens here."""
        entity_items = tuple(sorted(match.bindings.items()))
        entity_ids = tuple(entity.id for _, entity in entity_items)
        relationships = tuple(
            relationship.id
            for relationship in sorted(match.relationships, key=lambda item: item.id)
        )
        findings = tuple(
            sorted(
                {
                    finding
                    for relationship in match.relationships
                    for finding in relationship.supporting_findings
                }
            )
        )
        evidence = tuple(
            relationship.supporting_evidence
            for relationship in sorted(match.relationships, key=lambda r: r.id)
        )
        return Correlation(
            id=stable_correlation_id(rule.rule_id, entity_ids),
            rule_id=rule.rule_id,
            title=rule.title,
            description=rule.description,
            severity=rule.severity,
            confidence=rule.confidence,
            recommendation=rule.recommendation,
            mitre=rule.mitre,
            category=rule.category,
            tags=rule.tags,
            timestamp=datetime.now(UTC).replace(microsecond=0).isoformat(),
            matched_entities=tuple(
                {
                    "variable": variable,
                    "id": entity.id,
                    "entity_type": entity.entity_type.value,
                    "primary_identifier": entity.primary_identifier,
                }
                for variable, entity in entity_items
            ),
            matched_relationships=relationships,
            supporting_findings=findings,
            correlation_explanation={
                "triggered_rule": rule.rule_id,
                "stage": rule.stage.value,
                "matched_entities": [
                    {"variable": variable, "id": entity.id}
                    for variable, entity in entity_items
                ],
                "matched_relationships": list(relationships),
                "supporting_findings": list(findings),
                "supporting_evidence": [dict(item) for item in evidence],
            },
        )
