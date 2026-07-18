"""
core.score_factor
=================

ScoreFactor protocol and initial Milestone 7 factors.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..attack_chain.attack_chain import AttackChain
from ..foundation.finding import Confidence, Severity
from .risk_contribution import RiskContribution
from ..shared.stable_id import stable_sha_id

__all__ = [
    "ScoreFactor",
    "SeverityFactor",
    "ConfidenceFactor",
    "ExposureFactor",
    "CriticalAssetFactor",
    "MITREFactor",
    "ChainLengthFactor",
]


@runtime_checkable
class ScoreFactor(Protocol):
    """Evaluates one AttackChain and returns explainable risk contributions."""

    def evaluate(self, chain: AttackChain) -> tuple[RiskContribution, ...]:
        """Return one or more contributions for this factor."""


class SeverityFactor:
    """Score impact from the chain severity."""

    name = "severity"
    max_contribution = 40
    _scores = {
        Severity.LOW: 5,
        Severity.MEDIUM: 15,
        Severity.HIGH: 30,
        Severity.CRITICAL: 40,
    }

    def evaluate(self, chain: AttackChain) -> tuple[RiskContribution, ...]:
        """Return the capped severity contribution."""
        score = self._scores[chain.severity]
        return (
            _contribution(
                chain,
                self.name,
                score,
                self.max_contribution,
                f"{chain.severity.value} chain severity",
                "attack_chain.severity",
            ),
        )


class ConfidenceFactor:
    """Score certainty from the chain confidence."""

    name = "confidence"
    max_contribution = 15
    _scores = {
        Confidence.LOW: 5,
        Confidence.MEDIUM: 10,
        Confidence.HIGH: 15,
    }

    def evaluate(self, chain: AttackChain) -> tuple[RiskContribution, ...]:
        """Return the capped confidence contribution."""
        score = self._scores[chain.confidence]
        return (
            _contribution(
                chain,
                self.name,
                score,
                self.max_contribution,
                f"{chain.confidence.value} chain confidence",
                "attack_chain.confidence",
            ),
        )


class ExposureFactor:
    """Score whether the chain starts from an exposed entry point."""

    name = "exposure"
    max_contribution = 15

    def evaluate(self, chain: AttackChain) -> tuple[RiskContribution, ...]:
        """Return the capped exposure contribution."""
        stages = _timeline_stages(chain)
        exposed = "INITIAL_ACCESS" in stages

        reason = "Chain includes initial access" if exposed else "No initial access exposure found"

        if not exposed:
            mitre_techniques = chain.mitre_techniques
            if "T1046" in mitre_techniques:
                exposed = True
                reason = "Publicly exposed service detected"

        score = 15 if exposed else 0

        return (
            _contribution(
                chain,
                self.name,
                score,
                self.max_contribution,
                reason,
                "attack_chain.timeline",
            ),
        )


class CriticalAssetFactor:
    """Score chains that touch likely critical assets."""

    name = "critical_asset"
    max_contribution = 15
    _markers = (
        "admin",
        "critical",
        "database",
        "db",
        "domain",
        "prod",
        "root",
        "vault",
    )

    def evaluate(self, chain: AttackChain) -> tuple[RiskContribution, ...]:
        """Return the capped critical asset contribution."""
        assets = (chain.target, *chain.entities)
        critical_assets = tuple(
            asset
            for asset in assets
            if any(marker in asset.lower() for marker in self._markers)
        )
        score = 15 if critical_assets else 0
        reason = (
            f"Critical asset indicators: {', '.join(sorted(critical_assets))}"
            if critical_assets
            else "No critical asset indicator found"
        )
        return (
            _contribution(
                chain,
                self.name,
                score,
                self.max_contribution,
                reason,
                "attack_chain.target/entities",
            ),
        )


class MITREFactor:
    """Score mapped attack stages from the chain timeline."""

    name = "mitre"
    max_contribution = 10

    def evaluate(self, chain: AttackChain) -> tuple[RiskContribution, ...]:
        """Return the capped MITRE-stage coverage contribution."""
        stages = tuple(sorted(set(_timeline_stages(chain))))
        score = min(len(stages) * 2, self.max_contribution)
        return (
            _contribution(
                chain,
                self.name,
                score,
                self.max_contribution,
                f"{len(stages)} mapped attack stage(s)",
                "attack_chain.timeline.stage",
            ),
        )


class ChainLengthFactor:
    """Score longer attack chains without ranking them."""

    name = "chain_length"
    max_contribution = 5

    def evaluate(self, chain: AttackChain) -> tuple[RiskContribution, ...]:
        """Return the capped chain length contribution."""
        length = len(chain.correlations)
        score = min(max(length - 1, 0), self.max_contribution)
        return (
            _contribution(
                chain,
                self.name,
                score,
                self.max_contribution,
                f"{length} correlation(s) in chain",
                "attack_chain.correlations",
            ),
        )


def _contribution(
    chain: AttackChain,
    factor_name: str,
    score: int,
    max_contribution: int,
    reason: str,
    source: str,
) -> RiskContribution:
    """Build a clamped contribution owned by one factor."""
    clamped = max(0, min(score, max_contribution))
    return RiskContribution(
        id=_stable_contribution_id(chain.id, factor_name),
        factor_name=factor_name,
        score=clamped,
        max_contribution=max_contribution,
        reason=reason,
        source=source,
    )


def _stable_contribution_id(chain_id: str, factor_name: str) -> str:
    return stable_sha_id("risk-contribution", chain_id, factor_name)


def _timeline_stages(chain: AttackChain) -> tuple[str, ...]:
    return tuple(
        str(item["stage"])
        for item in chain.timeline
        if isinstance(item.get("stage"), str) and item["stage"].strip()
    )
