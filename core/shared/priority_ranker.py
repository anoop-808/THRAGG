"""
core.priority_ranker
====================

Priority ranking for RiskAssessment objects.
"""

from __future__ import annotations

from dataclasses import replace

from ..risk.risk_assessment import RiskAssessment

__all__ = ["PriorityRanker"]


class PriorityRanker:
    """Rank assessments by score descending."""

    def rank(
        self,
        assessments: tuple[RiskAssessment, ...],
    ) -> tuple[RiskAssessment, ...]:
        """Return copied assessments with deterministic priority ranks."""
        ordered = tuple(sorted(assessments, key=lambda item: (-item.score, item.id)))
        return tuple(
            replace(assessment, priority_rank=index)
            for index, assessment in enumerate(ordered, start=1)
        )
