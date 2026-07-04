"""
core.correlation_schema
=======================

Structural validation for Correlation objects.
"""

from __future__ import annotations

from .correlation import Correlation
from ..foundation.finding import Confidence, Severity

__all__ = [
    "CorrelationSchemaError",
    "validate_correlation",
    "is_valid_correlation",
]


class CorrelationSchemaError(ValueError):
    """Raised when a Correlation fails structural validation."""


def validate_correlation(correlation: Correlation) -> None:
    """Validate a Correlation without mutating it."""
    for field_name in (
        "id",
        "rule_id",
        "title",
        "description",
        "recommendation",
        "category",
        "timestamp",
    ):
        value = getattr(correlation, field_name)
        if not isinstance(value, str) or not value.strip():
            raise CorrelationSchemaError(
                f"Correlation.{field_name} must be a non-empty string"
            )

    if not isinstance(correlation.severity, Severity):
        raise CorrelationSchemaError("Correlation.severity must be a Severity enum")
    if not isinstance(correlation.confidence, Confidence):
        raise CorrelationSchemaError("Correlation.confidence must be a Confidence enum")

    _validate_string_tuple(correlation.mitre, "mitre")
    _validate_string_tuple(correlation.tags, "tags")
    _validate_string_tuple(correlation.matched_relationships, "matched_relationships")
    _validate_string_tuple(correlation.supporting_findings, "supporting_findings")

    if not isinstance(correlation.matched_entities, tuple) or not all(
        isinstance(entity, dict) for entity in correlation.matched_entities
    ):
        raise CorrelationSchemaError("Correlation.matched_entities must be tuple[dict]")
    if not isinstance(correlation.correlation_explanation, dict):
        raise CorrelationSchemaError("Correlation.correlation_explanation must be a dict")
    if not isinstance(correlation.is_duplicate, bool):
        raise CorrelationSchemaError("Correlation.is_duplicate must be a bool")


def is_valid_correlation(correlation: Correlation) -> bool:
    """Return True when a Correlation passes schema validation."""
    try:
        validate_correlation(correlation)
        return True
    except CorrelationSchemaError:
        return False


def _validate_string_tuple(value: object, field_name: str) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise CorrelationSchemaError(
            f"Correlation.{field_name} must be a tuple of non-empty strings"
        )
