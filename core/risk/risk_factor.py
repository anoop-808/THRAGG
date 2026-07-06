"""
core.risk.risk_factor
=====================

Shared factor protocol for likelihood and impact engines.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .risk_types import ChainData

__all__ = ["FactorContribution", "RiskFactor"]


@dataclass(frozen=True)
class FactorContribution:
    """Result produced by one detailed risk factor."""

    factor_name: str
    raw_score: float
    weighted_score: float
    weight: float
    reason: str
    source: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain data."""
        return {
            "factor_name": self.factor_name,
            "raw_score": self.raw_score,
            "weighted_score": self.weighted_score,
            "weight": self.weight,
            "reason": self.reason,
            "source": self.source,
        }


@runtime_checkable
class RiskFactor(Protocol):
    """Protocol all detailed risk factors implement."""

    name: str
    weight: float

    def evaluate(self, chain_data: ChainData) -> FactorContribution:
        """Evaluate normalized attack-chain data."""
