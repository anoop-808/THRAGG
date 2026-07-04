"""
core.risk_assessment
====================

Milestone 7 risk assessment model.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .risk_contribution import RiskContribution
from .risk_level import RiskLevel

__all__ = ["RiskAssessment"]


@dataclass(frozen=True)
class RiskAssessment:
    """Final M7 assessment data produced from risk contributions."""

    id: str
    attack_chain_id: str
    score: int
    risk_level: RiskLevel
    contributions: tuple[RiskContribution, ...]
    summary: str
    recommendation: str
    created_at: str
    policy_version: str
    priority_rank: int | None = None

    def __post_init__(self) -> None:
        """Defensively copy caller-owned contribution iterables."""
        object.__setattr__(self, "contributions", tuple(self.contributions))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "id": self.id,
            "attack_chain_id": self.attack_chain_id,
            "score": self.score,
            "risk_level": self.risk_level.value,
            "contributions": [
                contribution.to_dict() for contribution in self.contributions
            ],
            "summary": self.summary,
            "recommendation": self.recommendation,
            "created_at": self.created_at,
            "policy_version": self.policy_version,
            "priority_rank": self.priority_rank,
        }
