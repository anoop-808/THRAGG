"""
core.risk_builder
=================

Build RiskAssessment objects from AttackChain and ScoringPolicy inputs.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .attack_chain import AttackChain
from .risk_assessment import RiskAssessment
from .risk_level import RiskLevel
from .risk_schema import validate_risk_assessment, validate_risk_contribution
from .scoring_policy import ScoringPolicy
from .stable_id import stable_sha_id

__all__ = ["RiskBuilder", "RiskLevel", "stable_risk_assessment_id"]


def stable_risk_assessment_id(attack_chain_id: str, policy_version: str) -> str:
    """Return deterministic id for one chain scored under one policy version."""
    return stable_sha_id("risk", attack_chain_id, policy_version)


class RiskBuilder:
    """Collect contributions and construct one RiskAssessment."""

    def __init__(self, policy_version: str = "m7") -> None:
        self.policy_version = policy_version

    def build(
        self,
        chain: AttackChain,
        policy: ScoringPolicy,
        created_at: str | None = None,
    ) -> RiskAssessment:
        """Build one assessment. No ranking, storage, or orchestration."""
        contributions = tuple(
            contribution
            for factor in policy.factors
            for contribution in factor.evaluate(chain)
        )
        for contribution in contributions:
            validate_risk_contribution(contribution)

        score = min(sum(item.score for item in contributions), 100)
        assessment = RiskAssessment(
            id=stable_risk_assessment_id(chain.id, self.policy_version),
            attack_chain_id=chain.id,
            score=score,
            risk_level=self._risk_level(score),
            contributions=contributions,
            summary=f"Risk score {score} for attack chain {chain.id}.",
            recommendation=self._recommendation(chain),
            created_at=(
                created_at or datetime.now(UTC).replace(microsecond=0).isoformat()
            ),
            policy_version=self.policy_version,
        )
        validate_risk_assessment(assessment)
        return assessment

    def _risk_level(self, score: int) -> RiskLevel:
        if score >= 90:
            return RiskLevel.CRITICAL
        if score >= 70:
            return RiskLevel.HIGH
        if score >= 50:
            return RiskLevel.MEDIUM
        if score >= 25:
            return RiskLevel.LOW
        return RiskLevel.INFO

    def _recommendation(self, chain: AttackChain) -> str:
        if chain.recommendations:
            return chain.recommendations[0]
        return "Review the attack chain and remediate contributing findings."
