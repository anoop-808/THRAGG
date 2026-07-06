"""Risk package public API."""

from importlib import import_module
from typing import Any

_EXPORTS = {
    "AssetProfile": ".asset_profiles",
    "AssetRegistry": ".asset_registry",
    "ChainLengthFactor": ".score_factor",
    "ConfidenceFactor": ".score_factor",
    "ConfidenceScore": ".confidence_model",
    "CorrelationConfidenceModel": ".confidence_model",
    "CriticalAssetFactor": ".score_factor",
    "DEFAULT_SCORING_POLICY": ".risk_scoring_policy",
    "ExposureFactor": ".score_factor",
    "EnvironmentRiskAssessment": ".environment_risk_assessment",
    "EnvironmentRiskBuilder": ".environment_risk_builder",
    "FactorRegistry": ".risk_factor_registry",
    "ImpactEngine": ".risk_impact_engine",
    "ImpactScore": ".risk_impact_engine",
    "LikelihoodEngine": ".risk_likelihood_engine",
    "LikelihoodScore": ".risk_likelihood_engine",
    "MITREFactor": ".score_factor",
    "RiskAssessment": ".risk_assessment",
    "RiskBuilder": ".risk_builder",
    "RiskContribution": ".risk_contribution",
    "RiskEngine": ".risk_engine",
    "RiskLevel": ".risk_level",
    "RiskRepository": ".risk_repository",
    "RiskSchemaError": ".risk_schema",
    "RiskValidator": ".risk_schema",
    "ScoreFactor": ".score_factor",
    "ScoringPolicy": ".scoring_policy",
    "SeverityFactor": ".score_factor",
    "PriorityEngine": ".risk_priority_engine",
    "Policy": ".risk_policy",
    "PolicyAction": ".risk_policy",
    "PolicyEvaluationResult": ".risk_policy_engine",
    "PolicyLoader": ".risk_policy",
    "PolicyMatchCriteria": ".risk_policy",
    "PolicyType": ".risk_policy",
    "RiskPolicyEngine": ".risk_policy_engine",
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
