"""
core.executive.business_impact_engine
=====================================

Business impact translation for risk assessments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..risk.risk_assessment import RiskAssessment
from .business_language_registry import BusinessLanguageRegistry

__all__ = ["BusinessImpact", "BusinessImpactEngine"]


@dataclass(frozen=True)
class BusinessImpact:
    """Executive-safe business impact derived from one risk assessment."""

    risk_id: str
    impact: str
    business_context: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain data."""
        return {
            "risk_id": self.risk_id,
            "impact": self.impact,
            "business_context": self.business_context,
        }


class BusinessImpactEngine:
    """Translate technical risk wording into business impact language."""

    def __init__(self, registry: BusinessLanguageRegistry | None = None) -> None:
        self.registry = registry or BusinessLanguageRegistry()

    def build(self, risks: tuple[RiskAssessment, ...]) -> tuple[BusinessImpact, ...]:
        """Return deterministic business impacts for risks."""
        return tuple(
            BusinessImpact(
                risk_id=risk.id,
                impact=self.registry.impact_for_text(_risk_text(risk)),
                business_context=self.registry.translate_text(risk.summary),
            )
            for risk in sorted(risks, key=lambda item: (-item.score, item.id))
        )


def _risk_text(risk: RiskAssessment) -> str:
    action = getattr(risk, "suggested_action", risk.recommendation)
    return f"{risk.summary} {action}"
