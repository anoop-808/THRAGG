"""
core.environment_risk_builder
=============================

Deterministic environmental risk scoring.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..attack_chain.attack_chain import AttackChain
from ..shared.stable_id import stable_sha_id
from .environment_risk_assessment import EnvironmentRiskAssessment
from .risk_assessment import RiskAssessment
from .risk_contribution import RiskContribution
from .risk_level import RiskLevel

__all__ = ["EnvironmentRiskBuilder"]

FORMULA = (
    "overall_score = min(100, highest_chain_score + correlated_findings "
    "+ affected_assets + attack_chain_strength + public_exposure "
    "+ identity_weakness + cross_module_corroboration). "
    "Caps: correlated_findings 10, affected_assets 10, attack_chain_strength 20, "
    "public_exposure 10, identity_weakness 10, cross_module_corroboration 10."
)


class EnvironmentRiskBuilder:
    """Build one environment risk assessment from intelligence objects."""

    def __init__(self, policy_version: str = "intelligence-v1") -> None:
        self.policy_version = policy_version

    def build(
        self,
        risk_assessments: tuple[RiskAssessment, ...],
        attack_chains: tuple[AttackChain, ...],
        generated_at: str | None = None,
    ) -> EnvironmentRiskAssessment:
        """Return the overall risk rollup."""
        generated_at = (
            generated_at or datetime.now(UTC).replace(microsecond=0).isoformat()
        )
        factors = self._factors(risk_assessments, attack_chains)
        score = min(100, sum(item.score for item in factors))
        chain_contributions = self._chain_contributions(risk_assessments)
        entity_contributions = self._entity_contributions(attack_chains)
        return EnvironmentRiskAssessment(
            id=stable_sha_id(
                "env-risk",
                self.policy_version,
                *sorted(item.id for item in risk_assessments),
                *sorted(item.id for item in attack_chains),
            ),
            overall_score=score,
            risk_level=_risk_level(score),
            contributing_factors=factors,
            per_chain_contribution=chain_contributions,
            per_entity_contribution=entity_contributions,
            formula=FORMULA,
            generated_at=generated_at,
            policy_version=self.policy_version,
        )

    def _factors(
        self,
        risks: tuple[RiskAssessment, ...],
        chains: tuple[AttackChain, ...],
    ) -> tuple[RiskContribution, ...]:
        highest = max((risk.score for risk in risks), default=0)
        findings = {item for chain in chains for item in chain.supporting_findings}
        entities = {item for chain in chains for item in chain.entities}
        strength = max(
            (
                min(
                    len(chain.correlations) * 5
                    + sum(edge.affinity_score for edge in chain.chain_edges),
                    20,
                )
                for chain in chains
            ),
            default=0,
        )
        stages = {
            str(item.get("stage"))
            for chain in chains
            for item in chain.timeline
            if item.get("stage")
        }
        public_exposure = 10 if "INITIAL_ACCESS" in stages else 0
        identity_weakness = 10 if "CREDENTIAL_ACCESS" in stages else 0
        corroboration = min(
            len({risk.attack_chain_id for risk in risks if risk.score > 0}) * 5,
            10,
        )
        return (
            _contribution(
                "highest_chain_score",
                highest,
                100,
                "Highest per-chain risk score",
            ),
            _contribution(
                "correlated_findings",
                min(len(findings), 10),
                10,
                f"{len(findings)} correlated finding(s)",
            ),
            _contribution(
                "affected_assets",
                min(len(entities) * 2, 10),
                10,
                f"{len(entities)} affected asset(s)",
            ),
            _contribution(
                "attack_chain_strength",
                strength,
                20,
                "Strongest chain length plus relationship affinity",
            ),
            _contribution(
                "public_exposure",
                public_exposure,
                10,
                "Initial access stage present"
                if public_exposure
                else "No initial access stage",
            ),
            _contribution(
                "identity_weakness",
                identity_weakness,
                10,
                "Credential access stage present"
                if identity_weakness
                else "No credential access stage",
            ),
            _contribution(
                "cross_module_corroboration",
                corroboration,
                10,
                "Multiple scored chains corroborate risk",
            ),
        )

    def _chain_contributions(
        self,
        risks: tuple[RiskAssessment, ...],
    ) -> tuple[RiskContribution, ...]:
        return tuple(
            RiskContribution(
                id=stable_sha_id("env-risk-chain", risk.attack_chain_id),
                factor_name="per_chain",
                score=risk.score,
                max_contribution=100,
                reason=f"{risk.risk_level.value} chain risk",
                source=risk.attack_chain_id,
            )
            for risk in sorted(risks, key=lambda item: item.attack_chain_id)
        )

    def _entity_contributions(
        self,
        chains: tuple[AttackChain, ...],
    ) -> tuple[RiskContribution, ...]:
        entity_scores: dict[str, int] = {}
        for chain in chains:
            for entity in chain.entities:
                entity_scores[entity] = min(entity_scores.get(entity, 0) + 5, 100)
        return tuple(
            RiskContribution(
                id=stable_sha_id("env-risk-entity", entity),
                factor_name="per_entity",
                score=score,
                max_contribution=100,
                reason="Entity participates in attack chain(s)",
                source=entity,
            )
            for entity, score in sorted(entity_scores.items())
        )


def _contribution(
    name: str,
    score: int,
    max_contribution: int,
    reason: str,
) -> RiskContribution:
    return RiskContribution(
        id=stable_sha_id("env-risk-factor", name),
        factor_name=name,
        score=max(0, min(score, max_contribution)),
        max_contribution=max_contribution,
        reason=reason,
        source="environment",
    )


def _risk_level(score: int) -> RiskLevel:
    if score >= 90:
        return RiskLevel.CRITICAL
    if score >= 70:
        return RiskLevel.HIGH
    if score >= 50:
        return RiskLevel.MEDIUM
    if score >= 25:
        return RiskLevel.LOW
    return RiskLevel.INFO
