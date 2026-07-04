"""
core.scoring_policy
===================

Static scoring policy for Milestone 7.
"""

from __future__ import annotations

from dataclasses import dataclass

from .score_factor import ScoreFactor

__all__ = ["ScoringPolicy"]


@dataclass(frozen=True)
class ScoringPolicy:
    """A deterministic tuple of ScoreFactor objects."""

    factors: tuple[ScoreFactor, ...]

    def __post_init__(self) -> None:
        """Defensively copy caller-owned iterables."""
        object.__setattr__(self, "factors", tuple(self.factors))
