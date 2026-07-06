"""
core.executive.executive_assessment
===================================

Executive Assessment contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..shared.stable_id import stable_sha_id
from .assessment_scope import AssessmentScope
from .business_impact_engine import BusinessImpact
from .framework_statistics import FrameworkStatistics
from .observation import Observation
from .recommendation_registry import Recommendation
from .security_posture import SecurityPosture

__all__ = [
    "ExecutiveAssessment",
    "ExecutiveRisk",
    "stable_executive_assessment_id",
]


def stable_executive_assessment_id(*parts: str) -> str:
    """Return a deterministic ExecutiveAssessment id."""
    return stable_sha_id("exec", *parts)


@dataclass(frozen=True)
class ExecutiveRisk:
    """Executive-safe representation of a RiskAssessment."""

    risk_id: str
    risk_level: str
    score: int
    summary: str
    suggested_action: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain data."""
        return {
            "risk_id": self.risk_id,
            "risk_level": self.risk_level,
            "score": self.score,
            "summary": self.summary,
            "suggested_action": self.suggested_action,
        }


@dataclass(frozen=True, init=False)
class ExecutiveAssessment:
    """Risk-only executive interpretation output."""

    assessment_id: str
    security_posture: SecurityPosture
    overall_summary: str
    business_impact: tuple[BusinessImpact, ...]
    top_risks: tuple[ExecutiveRisk, ...]
    top_priorities: tuple[str, ...]
    executive_observations: tuple[str, ...]
    executive_recommendations: tuple[Recommendation, ...]
    assessment_scope: AssessmentScope
    metadata: dict[str, Any]
    observations: tuple[Observation, ...]
    statistics: FrameworkStatistics | None
    traceability: Any
    engine_version: str

    def __init__(
        self,
        assessment_id: str | None = None,
        security_posture: SecurityPosture | None = None,
        overall_summary: str | None = None,
        business_impact: tuple[BusinessImpact, ...] = (),
        top_risks: tuple[ExecutiveRisk, ...] = (),
        top_priorities: tuple[str, ...] = (),
        executive_observations: tuple[str, ...] = (),
        executive_recommendations: tuple[Recommendation, ...] = (),
        assessment_scope: AssessmentScope | None = None,
        metadata: dict[str, Any] | None = None,
        *,
        id: str | None = None,
        summary: str | None = None,
        observations: tuple[Observation, ...] = (),
        recommendations: tuple[str, ...] = (),
        statistics: FrameworkStatistics | None = None,
        traceability: Any = None,
        engine_version: str = "executive-v1",
        generated_at: str | None = None,
    ) -> None:
        """Accept the new contract and legacy constructor names."""
        final_id = assessment_id or id
        final_summary = overall_summary or summary
        final_time = (
            assessment_scope.assessment_time
            if assessment_scope is not None
            else generated_at
        )
        if final_time is None:
            final_time = ""
        if assessment_scope is None:
            assessment_scope = AssessmentScope((), (), (), (), final_time)
        if not executive_recommendations and recommendations:
            executive_recommendations = tuple(
                Recommendation(
                    id=f"LEGACY-{index}",
                    title=item,
                    description=item,
                    priority="Medium",
                    business_reason=item,
                    technical_reason=item,
                    expected_benefit=item,
                    references=(),
                    match_terms=(),
                )
                for index, item in enumerate(recommendations, start=1)
            )
        object.__setattr__(self, "assessment_id", final_id or "")
        object.__setattr__(
            self,
            "security_posture",
            security_posture or SecurityPosture.EXCELLENT,
        )
        object.__setattr__(self, "overall_summary", final_summary or "")
        object.__setattr__(self, "business_impact", tuple(business_impact))
        object.__setattr__(self, "top_risks", tuple(top_risks))
        object.__setattr__(self, "top_priorities", tuple(top_priorities))
        object.__setattr__(
            self,
            "executive_observations",
            tuple(executive_observations),
        )
        object.__setattr__(
            self,
            "executive_recommendations",
            tuple(executive_recommendations),
        )
        object.__setattr__(self, "assessment_scope", assessment_scope)
        object.__setattr__(self, "metadata", dict(metadata or {}))
        object.__setattr__(self, "observations", tuple(observations))
        object.__setattr__(self, "statistics", statistics)
        object.__setattr__(self, "traceability", traceability)
        object.__setattr__(self, "engine_version", engine_version)

    @property
    def id(self) -> str:
        """Backward-compatible id alias."""
        return self.assessment_id

    @property
    def summary(self) -> str:
        """Backward-compatible summary alias."""
        return self.overall_summary

    @property
    def recommendations(self) -> tuple[str, ...]:
        """Backward-compatible recommendation title alias."""
        return tuple(item.title for item in self.executive_recommendations)

    @property
    def generated_at(self) -> str:
        """Backward-compatible generated timestamp alias."""
        return self.assessment_scope.assessment_time

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain data without rendering a report."""
        data: dict[str, Any] = {
            "assessment_id": self.assessment_id,
            "security_posture": self.security_posture.value,
            "overall_summary": self.overall_summary,
            "business_impact": [item.to_dict() for item in self.business_impact],
            "top_risks": [item.to_dict() for item in self.top_risks],
            "top_priorities": list(self.top_priorities),
            "executive_observations": list(self.executive_observations),
            "executive_recommendations": [
                item.to_dict() for item in self.executive_recommendations
            ],
            "assessment_scope": self.assessment_scope.to_dict(),
            "metadata": dict(self.metadata),
            "id": self.id,
            "summary": self.summary,
            "recommendations": list(self.recommendations),
            "engine_version": self.engine_version,
            "generated_at": self.generated_at,
            "overall_security_posture": self.security_posture.value,
            "highest_priority_recommendations": list(self.recommendations[:5]),
            "executive_summary": self.summary,
        }
        if self.statistics is not None:
            data["statistics"] = self.statistics.to_dict()
            data["risk_distribution"] = [
                item.to_dict() for item in self.statistics.risk_counts
            ]
            data["most_critical_assets"] = [
                item.to_dict() for item in self.statistics.top_entity_types[:5]
            ]
            data["mitre_attack_coverage"] = [
                item.to_dict() for item in self.statistics.top_attack_stages
            ]
            data["environmental_health"] = self.security_posture.value
        if self.observations:
            data["observations"] = [
                observation.to_dict() for observation in self.observations
            ]
            data["primary_attack_paths"] = [
                observation.to_dict() for observation in self.observations[:5]
            ]
        if self.traceability is not None:
            data["traceability"] = {
                "observation_to_risks": [
                    (key, list(items))
                    for key, items in self.traceability.observation_to_risks
                ],
                "observation_to_attack_chains": [
                    (key, list(items))
                    for key, items in self.traceability.observation_to_attack_chains
                ],
                "observation_to_correlations": [
                    (key, list(items))
                    for key, items in self.traceability.observation_to_correlations
                ],
                "recommendation_to_observations": [
                    (key, list(items))
                    for key, items in self.traceability.recommendation_to_observations
                ],
            }
        return data
