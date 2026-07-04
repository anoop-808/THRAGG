"""
core.risk_contribution
======================

Explainable scoring contribution emitted by one ScoreFactor.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["RiskContribution"]


@dataclass(frozen=True)
class RiskContribution:
    """One immutable, deterministic piece of a risk score."""

    id: str
    factor_name: str
    score: int
    max_contribution: int
    reason: str
    source: str

    def to_dict(self) -> dict[str, object]:
        """Serialize to a plain dictionary."""
        return {
            "id": self.id,
            "factor_name": self.factor_name,
            "score": self.score,
            "max_contribution": self.max_contribution,
            "reason": self.reason,
            "source": self.source,
        }
