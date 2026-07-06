"""Deterministic confidence scoring for correlation objects."""

from __future__ import annotations

from dataclasses import dataclass

from .correlation_rule import CorrelationRule
from ..foundation.core_relationship_fact import RelationshipFact
from ..foundation.finding import Confidence
from ..foundation.resolved_entity import ResolvedEntity

__all__ = ["ConfidenceScore", "CorrelationConfidenceModel"]


_CONFIDENCE_POINTS = {
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}


@dataclass(frozen=True)
class ConfidenceScore:
    """Deterministic score with an enum label and audit factors."""

    value: int
    label: Confidence
    factors: dict[str, int]


class CorrelationConfidenceModel:
    """Score confidence from corroboration, match quality, relationships, and rule."""

    def score(
        self,
        *,
        entities: tuple[ResolvedEntity, ...],
        relationships: tuple[RelationshipFact, ...],
        rule: CorrelationRule,
    ) -> ConfidenceScore:
        """Return a reproducible confidence score."""
        modules = {module for entity in entities for module in entity.source_modules}
        match_strength = (
            3 if any(entity.resolution_records for entity in entities) else 2
        )
        relationship_quality = min(
            3,
            max(
                (_CONFIDENCE_POINTS.get(rel.confidence, 1) for rel in relationships),
                default=1,
            ),
        )
        factors = {
            "corroborating_modules": min(len(modules), 3),
            "entity_match_strength": match_strength,
            "relationship_quality": relationship_quality,
            "rule_confidence": _CONFIDENCE_POINTS[rule.confidence],
        }
        value = sum(factors.values())
        if value >= 10:
            label = Confidence.HIGH
        elif value >= 7:
            label = Confidence.MEDIUM
        else:
            label = Confidence.LOW
        return ConfidenceScore(value=value, label=label, factors=factors)
