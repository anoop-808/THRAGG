"""
core.risk.risk_calculator
==========================

Combines LikelihoodScore and ImpactScore into a deterministic final risk score.

Formula: risk_score = (likelihood * weight) + (impact * weight)

Weights, thresholds, and normalization now live in a ScoringPolicy
(see scoring_policy.py) instead of being hardcoded here. RiskCalculator
EXECUTES a policy — it does not own the numbers. Bump the policy's
version (== CALCULATION_VERSION) when weights or thresholds change.

Backward compatibility:
  - RiskCalculator() with no args behaves exactly as before (same weights,
    same thresholds, same rounding).
  - RiskLevel, score_to_level(), LIKELIHOOD_WEIGHT, IMPACT_WEIGHT, and
    CALCULATION_VERSION are all still importable from this module.
"""

from __future__ import annotations

from dataclasses import dataclass

from .risk_enums import RiskLevel
from .risk_version import CALCULATION_VERSION
from .risk_scoring_policy import DEFAULT_SCORING_POLICY, ScoringPolicy
from .risk_likelihood_engine import LikelihoodScore
from .risk_impact_engine import ImpactScore

# ── Backward-compatible module-level constants ─────────────────────────────
# These mirror DEFAULT_SCORING_POLICY exactly. Prefer ScoringPolicy for new
# code; these remain so `from .risk_calculator import LIKELIHOOD_WEIGHT`
# (or similar) does not break.
LIKELIHOOD_WEIGHT: float = DEFAULT_SCORING_POLICY.likelihood_weight
IMPACT_WEIGHT: float = DEFAULT_SCORING_POLICY.impact_weight

assert abs(LIKELIHOOD_WEIGHT + IMPACT_WEIGHT - 1.0) < 1e-9, (
    "LIKELIHOOD_WEIGHT + IMPACT_WEIGHT must equal 1.0"
)

# RiskLevel now lives in enums.py; re-exported here for backward compatibility.
__all__ = [
    "RiskLevel", "RiskScore", "RiskCalculator", "score_to_level",
    "LIKELIHOOD_WEIGHT", "IMPACT_WEIGHT", "CALCULATION_VERSION",
]


def score_to_level(score: float, policy: ScoringPolicy = DEFAULT_SCORING_POLICY) -> RiskLevel:
    """Map a numeric score (0-100) to a RiskLevel enum. Deterministic."""
    return policy.score_to_level(score)


@dataclass(frozen=True)
class RiskScore:
    """
    Final combined risk score produced by RiskCalculator.
    Stores the contributing likelihood and impact scores for full traceability.
    """
    score: float                  # 0.0 - 100.0
    level: RiskLevel
    likelihood_score: float
    impact_score: float
    calculation_version: str


class RiskCalculator:
    """
    Single responsibility: combine likelihood + impact → RiskScore.
    No factor logic lives here. Scoring weights/thresholds are supplied by
    a ScoringPolicy, defaulting to DEFAULT_SCORING_POLICY for full
    backward compatibility.
    """

    def __init__(self, policy: ScoringPolicy = DEFAULT_SCORING_POLICY) -> None:
        self._policy = policy

    @property
    def policy(self) -> ScoringPolicy:
        return self._policy

    def calculate(
        self,
        likelihood: LikelihoodScore,
        impact: ImpactScore,
    ) -> RiskScore:
        raw = self._policy.combine(likelihood.score, impact.score)
        final = self._policy.normalize(raw)
        return RiskScore(
            score=final,
            level=self._policy.score_to_level(final),
            likelihood_score=likelihood.score,
            impact_score=impact.score,
            calculation_version=self._policy.version,
        )
