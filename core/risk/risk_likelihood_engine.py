"""
core.risk.likelihood_engine
============================

Evaluates all likelihood factors and produces a normalized LikelihoodScore.
Accepts any tuple of RiskFactor implementations — no hardcoded factor list.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .risk_factor import FactorContribution, RiskFactor
from .risk_factor_registry import DEFAULT_FACTOR_REGISTRY


@dataclass(frozen=True)
class LikelihoodScore:
    """Result of LikelihoodEngine evaluation."""
    score: float                              # 0.0 - 100.0
    contributions: tuple[FactorContribution, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "contributions", tuple(self.contributions))


def _default_likelihood_factors() -> tuple[RiskFactor, ...]:
    """Delegates to FactorRegistry — kept as a thin wrapper for backward
    compatibility with any code importing this function directly."""
    return DEFAULT_FACTOR_REGISTRY.likelihood_factors()


class LikelihoodEngine:
    """
    Sums weighted factor scores into a single likelihood score (0-100).
    Factor weights must sum to 1.0 for the score to be meaningful.
    Unknown or missing factors produce a score of 0 for that contribution.
    """

    def __init__(self, factors: tuple[RiskFactor, ...] | None = None) -> None:
        self._factors = factors if factors is not None else _default_likelihood_factors()
        self._validate_weights()

    def _validate_weights(self) -> None:
        total = sum(f.weight for f in self._factors)
        if abs(total - 1.0) > 0.01:
            import warnings
            warnings.warn(
                f"LikelihoodEngine factor weights sum to {total:.3f}, not 1.0. "
                "Scores will not be properly normalized.",
                stacklevel=2,
            )

    def evaluate(self, chain_data: dict[str, Any]) -> LikelihoodScore:
        """Return a LikelihoodScore from all factor evaluations."""
        contributions: list[FactorContribution] = []
        total = 0.0

        for factor in self._factors:
            contribution = factor.evaluate(chain_data)
            contributions.append(contribution)
            total += contribution.weighted_score

        return LikelihoodScore(
            score=round(min(total, 100.0), 2),
            contributions=tuple(contributions),
        )
