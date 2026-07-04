"""Correlation package public API."""

from importlib import import_module
from typing import Any

_EXPORTS = {
    "AttackStage": ".correlation_rule",
    "Correlation": ".correlation",
    "CorrelationBuilder": ".correlation_builder",
    "CorrelationEngine": ".correlation_engine",
    "CorrelationRepository": ".correlation_repository",
    "CorrelationRule": ".correlation_rule",
    "CorrelationSchemaError": ".correlation_schema",
    "EntityAttributeEqualsCondition": ".correlation_rule",
    "PatternEvaluator": ".pattern_evaluator",
    "PatternMatch": ".pattern_evaluator",
    "RelationshipEvidenceEqualsCondition": ".correlation_rule",
    "RelationshipPattern": ".correlation_rule",
    "RuleRegistry": ".correlation_rule",
    "correlation_rule_from_dict": ".correlation_rule",
    "is_valid_correlation": ".correlation_schema",
    "stable_correlation_id": ".correlation_builder",
    "validate_correlation": ".correlation_schema",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Load correlation symbols lazily to avoid package import cycles."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(_EXPORTS[name], __name__), name)
    globals()[name] = value
    return value
