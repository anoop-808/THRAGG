"""Risk package public API."""

from importlib import import_module
from typing import Any

_EXPORTS = {
    "ChainLengthFactor": ".score_factor",
    "ConfidenceFactor": ".score_factor",
    "ConfidenceScore": ".confidence_model",
    "CorrelationConfidenceModel": ".confidence_model",
    "CriticalAssetFactor": ".score_factor",
    "ExposureFactor": ".score_factor",
    "MITREFactor": ".score_factor",
    "RiskAssessment": ".risk_assessment",
    "RiskBuilder": ".risk_builder",
    "RiskContribution": ".risk_contribution",
    "RiskEngine": ".risk_engine",
    "RiskLevel": ".risk_level",
    "RiskRepository": ".risk_repository",
    "RiskSchemaError": ".risk_schema",
    "ScoreFactor": ".score_factor",
    "ScoringPolicy": ".scoring_policy",
    "SeverityFactor": ".score_factor",
    "is_valid_risk_assessment": ".risk_schema",
    "is_valid_risk_contribution": ".risk_schema",
    "is_valid_scoring_policy": ".risk_schema",
    "stable_risk_assessment_id": ".risk_builder",
    "validate_risk_assessment": ".risk_schema",
    "validate_risk_contribution": ".risk_schema",
    "validate_scoring_policy": ".risk_schema",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Load risk symbols lazily to avoid package import cycles."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(_EXPORTS[name], __name__), name)
    globals()[name] = value
    return value
