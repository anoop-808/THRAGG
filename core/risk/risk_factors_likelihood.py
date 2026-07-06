"""
core.risk.factors.likelihood_factors
=====================================

Likelihood factors: how probable is this attack chain to succeed?

Each factor reads from the normalized chain_data dict produced by RiskBuilder.
No factor reads AttackChain directly — keeps factors decoupled from the domain object.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .risk_factor import FactorContribution

_CONFIDENCE_SCORES = {
    "CONFIRMED": 100.0,
    "HIGH": 85.0,
    "MEDIUM": 60.0,
    "LOW": 35.0,
}

_STAGE_COMPLETENESS_SCORES = {
    1: 20.0,
    2: 40.0,
    3: 60.0,
    4: 80.0,
    5: 90.0,
}
_MAX_STAGE_SCORE = 95.0


@dataclass(frozen=True)
class InternetExposureFactor:
    """
    Score: 100 if chain has an internet-facing initial access point, 0 otherwise.
    High weight — internet exposure is the primary attack enabler.
    """
    name: str = "internet_exposure"
    weight: float = 0.30

    def evaluate(self, chain_data: dict[str, Any]) -> FactorContribution:
        exposed = chain_data.get("has_internet_exposure", False)
        raw = 100.0 if exposed else 0.0
        return FactorContribution(
            factor_name=self.name,
            raw_score=raw,
            weighted_score=raw * self.weight,
            weight=self.weight,
            reason="Chain entry point is internet-facing" if exposed else "No internet-facing entry point detected",
            source="chain_data.has_internet_exposure",
        )


@dataclass(frozen=True)
class IdentityPrivilegeFactor:
    """
    Score based on whether a privileged identity (admin, owner, root) participates.
    Privileged identities dramatically increase attack success probability.
    """
    name: str = "identity_privilege"
    weight: float = 0.25

    def evaluate(self, chain_data: dict[str, Any]) -> FactorContribution:
        has_privileged = chain_data.get("has_privileged_identity", False)
        privilege_level = chain_data.get("privilege_level", "none").lower()
        score_map = {"critical": 100.0, "high": 80.0, "medium": 55.0, "low": 30.0, "none": 0.0}
        raw = score_map.get(privilege_level, 50.0) if has_privileged else 0.0
        return FactorContribution(
            factor_name=self.name,
            raw_score=raw,
            weighted_score=raw * self.weight,
            weight=self.weight,
            reason=f"Privileged identity participation level: {privilege_level}" if has_privileged else "No privileged identity in chain",
            source="chain_data.has_privileged_identity",
        )


@dataclass(frozen=True)
class ChainConfidenceFactor:
    """
    Propagates AttackChain.confidence into likelihood.
    Contributes ONCE here — never duplicated in ImpactEngine.
    """
    name: str = "chain_confidence"
    weight: float = 0.25

    def evaluate(self, chain_data: dict[str, Any]) -> FactorContribution:
        confidence_str = (chain_data.get("confidence") or "MEDIUM").upper()
        raw = _CONFIDENCE_SCORES.get(confidence_str, 60.0)
        return FactorContribution(
            factor_name=self.name,
            raw_score=raw,
            weighted_score=raw * self.weight,
            weight=self.weight,
            reason=f"Attack chain confidence: {confidence_str}",
            source="chain_data.confidence",
        )


@dataclass(frozen=True)
class AttackChainCompletenessFactor:
    """
    Longer, more complete attack chains represent more realistic threats.
    Capped at 5 stages to avoid domination by long chains.
    """
    name: str = "chain_completeness"
    weight: float = 0.20

    def evaluate(self, chain_data: dict[str, Any]) -> FactorContribution:
        stage_count = min(chain_data.get("stage_count", 1), 5)
        raw = _STAGE_COMPLETENESS_SCORES.get(stage_count, _MAX_STAGE_SCORE)
        return FactorContribution(
            factor_name=self.name,
            raw_score=raw,
            weighted_score=raw * self.weight,
            weight=self.weight,
            reason=f"Attack chain spans {stage_count} stage(s)",
            source="chain_data.stage_count",
        )
