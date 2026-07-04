"""
core.risk_schema
================

Structural validation for Milestone 7 risk scoring objects.
"""

from __future__ import annotations

from .risk_assessment import RiskAssessment
from .risk_contribution import RiskContribution
from .risk_level import RiskLevel
from .scoring_policy import ScoringPolicy
from .score_factor import ScoreFactor

__all__ = [
    "RiskSchemaError",
    "validate_risk_contribution",
    "is_valid_risk_contribution",
    "validate_scoring_policy",
    "is_valid_scoring_policy",
    "validate_risk_assessment",
    "is_valid_risk_assessment",
]


class RiskSchemaError(ValueError):
    """Raised when a risk scoring object fails structural validation."""


def validate_risk_contribution(contribution: RiskContribution) -> None:
    """Validate a RiskContribution without mutating it."""
    for field_name in ("id", "factor_name", "reason", "source"):
        _non_empty_string(
            getattr(contribution, field_name),
            f"RiskContribution.{field_name}",
        )
    if not isinstance(contribution.score, int):
        raise RiskSchemaError("RiskContribution.score must be an int")
    if not isinstance(contribution.max_contribution, int):
        raise RiskSchemaError("RiskContribution.max_contribution must be an int")
    if contribution.max_contribution < 0:
        raise RiskSchemaError("RiskContribution.max_contribution must be non-negative")
    if not 0 <= contribution.score <= contribution.max_contribution:
        raise RiskSchemaError(
            "RiskContribution.score must be between 0 and max_contribution"
        )


def is_valid_risk_contribution(contribution: RiskContribution) -> bool:
    """Return True when a RiskContribution passes schema validation."""
    try:
        validate_risk_contribution(contribution)
        return True
    except RiskSchemaError:
        return False


def validate_scoring_policy(policy: ScoringPolicy) -> None:
    """Validate a ScoringPolicy without mutating it."""
    if not isinstance(policy.factors, tuple):
        raise RiskSchemaError("ScoringPolicy.factors must be a tuple")
    if not all(isinstance(factor, ScoreFactor) for factor in policy.factors):
        raise RiskSchemaError("ScoringPolicy.factors must contain ScoreFactor objects")


def is_valid_scoring_policy(policy: ScoringPolicy) -> bool:
    """Return True when a ScoringPolicy passes schema validation."""
    try:
        validate_scoring_policy(policy)
        return True
    except RiskSchemaError:
        return False


def validate_risk_assessment(assessment: RiskAssessment) -> None:
    """Validate a RiskAssessment without mutating it."""
    for field_name in (
        "id",
        "attack_chain_id",
        "summary",
        "recommendation",
        "created_at",
        "policy_version",
    ):
        _non_empty_string(
            getattr(assessment, field_name),
            f"RiskAssessment.{field_name}",
        )
    if not isinstance(assessment.score, int) or assessment.score < 0:
        raise RiskSchemaError("RiskAssessment.score must be a non-negative int")
    if not isinstance(assessment.risk_level, RiskLevel):
        raise RiskSchemaError("RiskAssessment.risk_level must be a RiskLevel enum")
    if assessment.priority_rank is not None and (
        not isinstance(assessment.priority_rank, int) or assessment.priority_rank < 1
    ):
        raise RiskSchemaError(
            "RiskAssessment.priority_rank must be a positive int or None"
        )
    if not isinstance(assessment.contributions, tuple):
        raise RiskSchemaError("RiskAssessment.contributions must be a tuple")
    for contribution in assessment.contributions:
        if not isinstance(contribution, RiskContribution):
            raise RiskSchemaError(
                "RiskAssessment.contributions must contain RiskContribution objects"
            )
        validate_risk_contribution(contribution)


def is_valid_risk_assessment(assessment: RiskAssessment) -> bool:
    """Return True when a RiskAssessment passes schema validation."""
    try:
        validate_risk_assessment(assessment)
        return True
    except RiskSchemaError:
        return False


def _non_empty_string(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RiskSchemaError(f"{field_name} must be a non-empty string")
