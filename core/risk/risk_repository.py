"""
core.risk_repository
====================

In-memory repository for RiskAssessment objects.
"""

from __future__ import annotations

from .risk_assessment import RiskAssessment

__all__ = ["RiskRepository"]


class RiskRepository:
    """Store RiskAssessment objects with deterministic retrieval."""

    def __init__(self) -> None:
        self._assessments: dict[str, RiskAssessment] = {}

    def add(self, assessment: RiskAssessment) -> bool:
        """Store one assessment, returning False for duplicate ids."""
        if assessment.id in self._assessments:
            return False
        self._assessments[assessment.id] = assessment
        return True

    def all(self) -> tuple[RiskAssessment, ...]:
        """Return assessments ordered deterministically."""
        return tuple(
            self._assessments[item_id]
            for item_id in sorted(self._assessments)
        )
