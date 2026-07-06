"""
core.executive.executive_builder
================================

Build ExecutiveAssessment from RiskAssessment objects.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..risk.risk_assessment import RiskAssessment
from .assessment_scope import AssessmentScope
from .business_impact_engine import BusinessImpactEngine
from .business_language_registry import BusinessLanguageRegistry
from .executive_assessment import (
    ExecutiveAssessment,
    ExecutiveRisk,
    stable_executive_assessment_id,
)
from .posture_calculator import PostureCalculator
from .recommendation_engine import RecommendationEngine

__all__ = ["ExecutiveBuilder"]


class ExecutiveBuilder:
    """Interpret risk assessments into executive assessment output."""

    def __init__(
        self,
        posture_calculator: PostureCalculator | None = None,
        business_impact_engine: BusinessImpactEngine | None = None,
        recommendation_engine: RecommendationEngine | None = None,
        language_registry: BusinessLanguageRegistry | None = None,
        engine_version: str = "executive-assessment-v1",
    ) -> None:
        self.posture_calculator = posture_calculator or PostureCalculator()
        self.business_impact_engine = business_impact_engine or BusinessImpactEngine()
        self.recommendation_engine = recommendation_engine or RecommendationEngine()
        self.language_registry = language_registry or BusinessLanguageRegistry()
        self.engine_version = engine_version

    def build(
        self,
        risks: tuple[RiskAssessment, ...],
        assessment_scope: AssessmentScope | None = None,
    ) -> ExecutiveAssessment:
        """Build one deterministic executive assessment."""
        risks = tuple(sorted(risks, key=lambda item: (-item.score, item.id)))
        assessment_scope = assessment_scope or AssessmentScope(
            modules_run=(),
            modules_skipped=(),
            evidence_files=(),
            assessment_limitations=("Assessment scope was not supplied.",),
            assessment_time=datetime.now(UTC).replace(microsecond=0).isoformat(),
        )
        posture = self.posture_calculator.calculate(risks)
        top_risks = self._top_risks(risks)
        recommendations = self.recommendation_engine.build(risks)
        return ExecutiveAssessment(
            assessment_id=stable_executive_assessment_id(
                self.engine_version,
                assessment_scope.assessment_time,
                *(risk.id for risk in risks),
            ),
            security_posture=posture,
            overall_summary=self._summary(posture, risks),
            business_impact=self.business_impact_engine.build(risks),
            top_risks=top_risks,
            top_priorities=tuple(item.title for item in recommendations[:5]),
            executive_observations=self._observations(risks),
            executive_recommendations=recommendations,
            assessment_scope=assessment_scope,
            metadata={
                "engine_version": self.engine_version,
                "risk_assessment_count": len(risks),
                "input_contract": "RiskAssessment[]",
            },
            engine_version=self.engine_version,
        )

    def _summary(
        self,
        posture: object,
        risks: tuple[RiskAssessment, ...],
    ) -> str:
        if not risks:
            return "No risk assessments were provided for executive interpretation."
        highest = risks[0]
        return (
            f"Overall security posture is {posture.value}. "
            f"The highest interpreted risk is {highest.risk_level.value} "
            f"with score {highest.score}."
        )

    def _top_risks(
        self,
        risks: tuple[RiskAssessment, ...],
    ) -> tuple[ExecutiveRisk, ...]:
        return tuple(
            ExecutiveRisk(
                risk_id=risk.id,
                risk_level=risk.risk_level.value,
                score=risk.score,
                summary=self.language_registry.translate_text(risk.summary),
                suggested_action=getattr(risk, "suggested_action", risk.recommendation),
            )
            for risk in risks[:5]
        )

    def _observations(self, risks: tuple[RiskAssessment, ...]) -> tuple[str, ...]:
        if not risks:
            return ("No interpreted risks were available for this assessment.",)
        return tuple(
            (
                f"{risk.risk_level.value.title()} risk requires executive visibility: "
                f"{self.language_registry.translate_text(risk.summary)}"
            )
            for risk in risks[:5]
        )
