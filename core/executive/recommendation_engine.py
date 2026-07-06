"""
core.executive.recommendation_engine
====================================

Recommendation selection for ExecutiveAssessment.
"""

from __future__ import annotations

from ..risk.risk_assessment import RiskAssessment
from .recommendation_registry import Recommendation, RecommendationRegistry

__all__ = ["RecommendationEngine"]


class RecommendationEngine:
    """Select registry recommendations from RiskAssessment content."""

    def __init__(self, registry: RecommendationRegistry | None = None) -> None:
        self.registry = registry or RecommendationRegistry()

    def build(self, risks: tuple[RiskAssessment, ...]) -> tuple[Recommendation, ...]:
        """Return unique registry recommendations in deterministic priority order."""
        selected: dict[str, Recommendation] = {}
        for risk in sorted(risks, key=lambda item: (-item.score, item.id)):
            action = getattr(risk, "suggested_action", risk.recommendation)
            for recommendation in self.registry.matching(f"{risk.summary} {action}"):
                selected.setdefault(recommendation.id, recommendation)
        return self.registry.order(tuple(selected.values()))
