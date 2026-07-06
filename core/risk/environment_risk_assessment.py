"""
core.environment_risk_assessment
================================

Environment-level risk rollup built from attack chains and risk assessments.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .risk_contribution import RiskContribution
from .risk_level import RiskLevel

__all__ = ["EnvironmentRiskAssessment"]


@dataclass(frozen=True)
class EnvironmentRiskAssessment:
    """Overall environmental risk with chain/entity drilldowns."""

    id: str
    overall_score: int
    risk_level: RiskLevel
    contributing_factors: tuple[RiskContribution, ...]
    per_chain_contribution: tuple[RiskContribution, ...]
    per_entity_contribution: tuple[RiskContribution, ...]
    formula: str
    generated_at: str
    policy_version: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "contributing_factors",
            tuple(self.contributing_factors),
        )
        object.__setattr__(
            self,
            "per_chain_contribution",
            tuple(self.per_chain_contribution),
        )
        object.__setattr__(
            self,
            "per_entity_contribution",
            tuple(self.per_entity_contribution),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain data."""
        return {
            "id": self.id,
            "overall_score": self.overall_score,
            "risk_level": self.risk_level.value,
            "contributing_factors": [
                item.to_dict() for item in self.contributing_factors
            ],
            "per_chain_contribution": [
                item.to_dict() for item in self.per_chain_contribution
            ],
            "per_entity_contribution": [
                item.to_dict() for item in self.per_entity_contribution
            ],
            "formula": self.formula,
            "generated_at": self.generated_at,
            "policy_version": self.policy_version,
        }
