"""
core.executive.executive_validator
==================================

Validation for risk-only ExecutiveAssessment objects.
"""

from __future__ import annotations

from .assessment_scope import AssessmentScope
from .business_impact_engine import BusinessImpact
from .executive_assessment import ExecutiveAssessment, ExecutiveRisk
from .recommendation_registry import Recommendation
from .security_posture import SecurityPosture

__all__ = ["ExecutiveValidationError", "ExecutiveValidator"]


class ExecutiveValidationError(ValueError):
    """Raised when ExecutiveAssessment validation fails."""


class ExecutiveValidator:
    """Validate the ExecutiveAssessment output contract."""

    def validate(self, assessment: ExecutiveAssessment) -> None:
        """Validate without mutating assessment."""
        _non_empty_string(assessment.assessment_id, "assessment_id")
        _non_empty_string(assessment.overall_summary, "overall_summary")
        if not isinstance(assessment.security_posture, SecurityPosture):
            raise ExecutiveValidationError("security_posture must be SecurityPosture")
        if not isinstance(assessment.assessment_scope, AssessmentScope):
            raise ExecutiveValidationError("assessment_scope must be AssessmentScope")
        _non_empty_string(
            assessment.assessment_scope.assessment_time,
            "assessment_scope.assessment_time",
        )
        _typed_tuple(assessment.business_impact, BusinessImpact, "business_impact")
        _typed_tuple(assessment.top_risks, ExecutiveRisk, "top_risks")
        _typed_tuple(
            assessment.executive_recommendations,
            Recommendation,
            "executive_recommendations",
        )
        _strings(assessment.top_priorities, "top_priorities")
        _strings(assessment.executive_observations, "executive_observations")


def _typed_tuple(value: object, item_type: type, field_name: str) -> None:
    if not isinstance(value, tuple) or not all(isinstance(item, item_type) for item in value):
        raise ExecutiveValidationError(f"{field_name} must be tuple[{item_type.__name__}]")


def _strings(value: object, field_name: str) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ExecutiveValidationError(f"{field_name} must be tuple[str, ...]")


def _non_empty_string(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ExecutiveValidationError(f"{field_name} must be a non-empty string")
