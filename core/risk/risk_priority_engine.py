"""
core.risk.risk_priority_engine
==============================

Determines investigation priority from effective_risk_score.
Priority is NOT the same as risk score.
Suppressed assessments are excluded from ranking.
Accepted-risk assessments are included but dampened.
"""

from __future__ import annotations

from .risk_assessment import RiskAssessment


class PriorityEngine:
    """
    Assigns priority ranks (1 = investigate first) to a list of RiskAssessments.
    Returns new frozen RiskAssessment objects with priority set.
    Suppressed assessments receive priority=0 (excluded from ranked list).
    """

    def rank(
        self, assessments: list[RiskAssessment]
    ) -> list[RiskAssessment]:
        """
        Sort by effective_risk_score descending, assign sequential ranks.
        Suppressed assessments are placed last with priority=0.
        Returns a new list — does not mutate inputs.
        """
        active = [a for a in assessments if not getattr(a, "suppressed", False)]
        suppressed = [a for a in assessments if getattr(a, "suppressed", False)]

        ranked_active = sorted(
            active,
            key=lambda a: (-_score(a), a.id),
        )

        result: list[RiskAssessment] = []
        for rank, assessment in enumerate(ranked_active, start=1):
            result.append(_with_priority(assessment, rank))

        for assessment in suppressed:
            result.append(_with_priority(assessment, 0))

        return result


def _with_priority(assessment: RiskAssessment, priority: int) -> RiskAssessment:
    """Return a new RiskAssessment with priority set. All other fields preserved."""
    from dataclasses import replace
    if hasattr(assessment, "priority_rank"):
        return replace(assessment, priority_rank=priority)
    return replace(assessment, priority=priority)


def _score(assessment: RiskAssessment) -> float:
    return float(getattr(assessment, "effective_risk_score", assessment.score))
