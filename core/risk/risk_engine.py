"""
core.risk_engine
================

Milestone 7 orchestration for risk scoring.
"""

from __future__ import annotations

from ..attack_chain.attack_chain import AttackChain
from ..shared.priority_ranker import PriorityRanker
from .environment_risk_assessment import EnvironmentRiskAssessment
from .environment_risk_builder import EnvironmentRiskBuilder
from .risk_assessment import RiskAssessment
from .risk_builder import RiskBuilder
from .risk_repository import RiskRepository
from .scoring_policy import ScoringPolicy

__all__ = ["RiskEngine"]


class RiskEngine:
    """Build, store, and rank risk assessments."""

    def __init__(
        self,
        builder: RiskBuilder | None = None,
        repository: RiskRepository | None = None,
        ranker: PriorityRanker | None = None,
    ) -> None:
        self.builder = builder or RiskBuilder()
        self.repository = repository or RiskRepository()
        self.ranker = ranker or PriorityRanker()

    def run(
        self,
        chains: tuple[AttackChain, ...],
        policy: ScoringPolicy,
    ) -> tuple[RiskAssessment, ...]:
        """Return ranked assessments for the supplied chains."""
        for chain in sorted(chains, key=lambda item: item.id):
            self.repository.add(self.builder.build(chain, policy))
        return self.ranker.rank(self.repository.all())

    def assess_environment(
        self,
        assessments: tuple[RiskAssessment, ...],
        chains: tuple[AttackChain, ...],
        generated_at: str | None = None,
    ) -> EnvironmentRiskAssessment:
        """Return the deterministic environmental rollup."""
        return EnvironmentRiskBuilder().build(assessments, chains, generated_at)
