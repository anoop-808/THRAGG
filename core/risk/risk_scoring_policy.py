"""
core.risk.scoring_policy
=========================

ScoringPolicy — the single reusable configuration object holding:
  - likelihood/impact weights used to combine into the final risk score
  - risk-level thresholds
  - score normalization behavior

RiskCalculator EXECUTES a ScoringPolicy. It does not own weights or
thresholds itself. This makes it possible to introduce a new scoring
policy version (e.g. "2.0") without touching RiskCalculator at all —
just build a new ScoringPolicy and pass it in.

Backward compatibility: RiskCalculator() with no arguments still uses
DEFAULT_SCORING_POLICY, whose values are identical to the previous
hardcoded constants (LIKELIHOOD_WEIGHT=0.40, IMPACT_WEIGHT=0.60), so
existing scores are bit-for-bit unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .risk_enums import RiskLevel
from .risk_version import CALCULATION_VERSION


@dataclass(frozen=True)
class RiskLevelThreshold:
    """One (minimum score, level) rule. Evaluated highest-threshold-first."""
    minimum_score: float
    level: RiskLevel


_DEFAULT_THRESHOLDS: tuple[RiskLevelThreshold, ...] = (
    RiskLevelThreshold(81.0, RiskLevel.CRITICAL),
    RiskLevelThreshold(61.0, RiskLevel.HIGH),
    RiskLevelThreshold(41.0, RiskLevel.MEDIUM),
    RiskLevelThreshold(21.0, RiskLevel.LOW),
    RiskLevelThreshold(0.0, RiskLevel.INFORMATIONAL),
)


@dataclass(frozen=True)
class ScoringPolicy:
    """
    Immutable scoring configuration consumed by RiskCalculator.

    likelihood_weight + impact_weight must equal 1.0 (validated at construction).
    thresholds must be sorted descending by minimum_score and must bottom
    out at 0.0 (validated at construction) so score_to_level() is total.
    """
    version: str
    likelihood_weight: float
    impact_weight: float
    thresholds: tuple[RiskLevelThreshold, ...] = field(default_factory=lambda: _DEFAULT_THRESHOLDS)
    max_score: float = 100.0
    min_score: float = 0.0

    def __post_init__(self) -> None:
        total = self.likelihood_weight + self.impact_weight
        if abs(total - 1.0) > 1e-9:
            raise ValueError(
                f"ScoringPolicy '{self.version}': likelihood_weight + impact_weight "
                f"must equal 1.0, got {total}"
            )
        sorted_desc = tuple(sorted(self.thresholds, key=lambda t: t.minimum_score, reverse=True))
        if sorted_desc != tuple(self.thresholds):
            raise ValueError(f"ScoringPolicy '{self.version}': thresholds must be sorted descending")
        if sorted_desc[-1].minimum_score != 0.0:
            raise ValueError(f"ScoringPolicy '{self.version}': thresholds must bottom out at 0.0")

    def combine(self, likelihood_score: float, impact_score: float) -> float:
        """Combine likelihood + impact into a raw (pre-clamp) risk score."""
        return (likelihood_score * self.likelihood_weight) + (impact_score * self.impact_weight)

    def normalize(self, raw_score: float) -> float:
        """Clamp raw_score into [min_score, max_score] and round to 1dp."""
        clamped = max(self.min_score, min(raw_score, self.max_score))
        return round(clamped, 1)

    def score_to_level(self, score: float) -> RiskLevel:
        """Map a numeric score to a RiskLevel using this policy's thresholds."""
        for threshold in self.thresholds:
            if score >= threshold.minimum_score:
                return threshold.level
        return RiskLevel.INFORMATIONAL


# Identical numeric behavior to the previous hardcoded constants —
# existing scores are unaffected by this refactor.
DEFAULT_SCORING_POLICY = ScoringPolicy(
    version=CALCULATION_VERSION,
    likelihood_weight=0.40,
    impact_weight=0.60,
    thresholds=_DEFAULT_THRESHOLDS,
)
