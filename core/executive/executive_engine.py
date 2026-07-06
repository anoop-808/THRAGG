"""
core.executive.executive_engine
===============================

Executive Assessment orchestration.
"""

from __future__ import annotations

from ..risk.risk_assessment import RiskAssessment
from .assessment_scope import AssessmentScope
from .executive_assessment import ExecutiveAssessment
from .executive_builder import ExecutiveBuilder
from .executive_repository import ExecutiveRepository
from .executive_validator import ExecutiveValidator

__all__ = ["ExecutiveEngine"]


class ExecutiveEngine:
    """Build, validate, and store executive assessments."""

    def __init__(
        self,
        builder: ExecutiveBuilder | None = None,
        repository: ExecutiveRepository | None = None,
        validator: ExecutiveValidator | None = None,
    ) -> None:
        self.builder = builder or ExecutiveBuilder()
        self.repository = repository or ExecutiveRepository()
        self.validator = validator or ExecutiveValidator()

    def run(
        self,
        risks: tuple[RiskAssessment, ...],
        assessment_scope: AssessmentScope | None = None,
    ) -> ExecutiveAssessment:
        """Return one ExecutiveAssessment from RiskAssessment inputs only."""
        assessment = self.builder.build(tuple(risks), assessment_scope)
        self.validator.validate(assessment)
        self.repository.add(assessment)
        return assessment
