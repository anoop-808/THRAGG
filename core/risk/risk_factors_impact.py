"""
core.risk.factors.impact_factors
==================================

Impact factors: how damaging would a successful attack be?
Impact is independent of likelihood and independent of confidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .risk_factor import FactorContribution

_ENTITY_TYPE_BLAST = {
    "DOMAIN_CONTROLLER": 100.0,
    "IDENTITY_PROVIDER": 100.0,
    "KEY_VAULT": 95.0,
    "DATABASE": 90.0,
    "CLOUD_RESOURCE": 80.0,
    "STORAGE": 80.0,
    "APPLICATION": 70.0,
    "HOST": 60.0,
    "SERVICE": 50.0,
    "NETWORK": 45.0,
    "CONTAINER": 55.0,
    "USER": 65.0,
}
_DEFAULT_ENTITY_BLAST = 50.0


@dataclass(frozen=True)
class AssetCriticalityFactor:
    """
    Derives impact from the most critical asset type in the chain.
    Uses AssetRegistry composite_impact when a named profile exists.
    Falls back to entity-type blast radius table.
    """
    name: str = "asset_criticality"
    weight: float = 0.35

    def evaluate(self, chain_data: dict[str, Any]) -> FactorContribution:
        # Primary: named asset profile composite_impact (provided by RiskBuilder)
        profile_impact = chain_data.get("primary_asset_composite_impact")
        if profile_impact is not None:
            raw = float(profile_impact)
            source = "asset_registry.primary_asset_profile"
            reason = f"Named asset profile composite impact: {raw:.1f}"
        else:
            # Fallback: highest entity type blast radius
            entity_types = chain_data.get("entity_types", [])
            blast_scores = [_ENTITY_TYPE_BLAST.get(et.upper(), _DEFAULT_ENTITY_BLAST) for et in entity_types]
            raw = max(blast_scores) if blast_scores else _DEFAULT_ENTITY_BLAST
            source = "chain_data.entity_types"
            reason = f"Highest entity-type blast radius across {len(entity_types)} entity type(s)"

        return FactorContribution(
            factor_name=self.name,
            raw_score=raw,
            weighted_score=raw * self.weight,
            weight=self.weight,
            reason=reason,
            source=source,
        )


@dataclass(frozen=True)
class BlastRadiusFactor:
    """
    More distinct entity types = broader blast radius = higher impact.
    Saturates at 5+ distinct types.
    """
    name: str = "blast_radius"
    weight: float = 0.25

    def evaluate(self, chain_data: dict[str, Any]) -> FactorContribution:
        distinct_types = len(set(chain_data.get("entity_types", [])))
        # Score: 20 per distinct type, capped at 100
        raw = min(distinct_types * 20.0, 100.0)
        return FactorContribution(
            factor_name=self.name,
            raw_score=raw,
            weighted_score=raw * self.weight,
            weight=self.weight,
            reason=f"{distinct_types} distinct entity type(s) in chain",
            source="chain_data.entity_types",
        )


@dataclass(frozen=True)
class SeverityFactor:
    """
    Chain severity directly informs impact magnitude.
    Severity comes from AttackChain — not recalculated.
    """
    name: str = "chain_severity"
    weight: float = 0.25

    _SEVERITY_MAP = {
        "CRITICAL": 100.0,
        "HIGH": 80.0,
        "MEDIUM": 55.0,
        "LOW": 30.0,
        "INFORMATIONAL": 10.0,
    }

    def evaluate(self, chain_data: dict[str, Any]) -> FactorContribution:
        severity = (chain_data.get("severity") or "MEDIUM").upper()
        raw = self._SEVERITY_MAP.get(severity, 55.0)
        return FactorContribution(
            factor_name=self.name,
            raw_score=raw,
            weighted_score=raw * self.weight,
            weight=self.weight,
            reason=f"Attack chain severity: {severity}",
            source="chain_data.severity",
        )


@dataclass(frozen=True)
class EnvironmentFactor:
    """
    Production environments have higher impact than staging or test.
    Derived from the primary asset's environment field.
    """
    name: str = "environment"
    weight: float = 0.15

    _ENV_MAP = {
        "prod": 100.0,
        "production": 100.0,
        "staging": 60.0,
        "dev": 30.0,
        "development": 30.0,
        "test": 15.0,
        "unknown": 50.0,
    }

    def evaluate(self, chain_data: dict[str, Any]) -> FactorContribution:
        env = (chain_data.get("primary_asset_environment") or "unknown").lower()
        raw = self._ENV_MAP.get(env, 50.0)
        return FactorContribution(
            factor_name=self.name,
            raw_score=raw,
            weighted_score=raw * self.weight,
            weight=self.weight,
            reason=f"Primary asset environment: {env}",
            source="chain_data.primary_asset_environment",
        )
