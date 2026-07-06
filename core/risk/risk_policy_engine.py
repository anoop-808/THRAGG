"""
core.risk.risk_policy_engine
============================

Policy evaluation for the Risk Engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .risk_policy import Policy, PolicyAction

__all__ = ["PolicyEvaluationResult", "RiskPolicyEngine"]

ACCEPTED_RISK_DAMPENER = 0.50


@dataclass(frozen=True)
class PolicyEvaluationResult:
    """Result of evaluating policies against one chain."""

    applied_policies: tuple[Policy, ...]
    accepted_risk: bool
    suppressed: bool
    effective_score: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "applied_policies", tuple(self.applied_policies))


class RiskPolicyEngine:
    """Evaluate policy objects against normalized attack-chain data."""

    def __init__(self, policies: tuple[Policy, ...] = ()) -> None:
        self._policies = tuple(policies)

    def evaluate(
        self,
        chain_data: dict[str, Any],
        base_score: float,
    ) -> PolicyEvaluationResult:
        """Return effective score and applied policy metadata."""
        applied: list[Policy] = []
        accepted_risk = False
        suppressed = False
        score_modifier_total = 0.0

        for policy in self._policies:
            if not policy.match_criteria.matches(chain_data):
                continue
            applied.append(policy)
            if policy.action is PolicyAction.SUPPRESS:
                suppressed = True
                break
            if policy.action is PolicyAction.ACCEPT:
                accepted_risk = True
            if policy.action is PolicyAction.DOWNGRADE:
                score_modifier_total += policy.score_modifier

        effective = base_score + score_modifier_total
        if accepted_risk and not suppressed:
            effective *= ACCEPTED_RISK_DAMPENER
        return PolicyEvaluationResult(
            applied_policies=tuple(applied),
            accepted_risk=accepted_risk,
            suppressed=suppressed,
            effective_score=round(max(0.0, min(effective, 100.0)), 1),
        )
