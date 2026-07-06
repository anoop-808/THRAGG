"""
core.executive.executive_repository
===================================

In-memory repository for ExecutiveAssessment objects.
"""

from __future__ import annotations

from .executive_assessment import ExecutiveAssessment

__all__ = ["ExecutiveRepository"]


class ExecutiveRepository:
    """Store ExecutiveAssessment objects with deterministic retrieval."""

    def __init__(self) -> None:
        self._assessments: dict[str, ExecutiveAssessment] = {}

    def add(self, assessment: ExecutiveAssessment) -> bool:
        """Store one assessment, returning False for duplicate ids."""
        if assessment.assessment_id in self._assessments:
            return False
        self._assessments[assessment.assessment_id] = assessment
        return True

    def all(self) -> tuple[ExecutiveAssessment, ...]:
        """Return assessments ordered by id."""
        return tuple(
            self._assessments[item_id]
            for item_id in sorted(self._assessments)
        )
