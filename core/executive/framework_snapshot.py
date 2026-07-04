"""
core.framework_snapshot
=======================

Immutable Milestone 8 input snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..attack_chain.attack_chain import AttackChain
from ..correlation.correlation import Correlation
from ..risk.risk_assessment import RiskAssessment

__all__ = ["FrameworkSnapshot"]


@dataclass(frozen=True)
class FrameworkSnapshot:
    """Single immutable input for Milestone 8 builders."""

    risk_assessments: tuple[RiskAssessment, ...]
    attack_chains: tuple[AttackChain, ...]
    correlations: tuple[Correlation, ...]
    finding_count: int
    entity_count: int
    resolved_entity_count: int
    relationship_count: int
    snapshot_version: str
    generated_at: str

    def __post_init__(self) -> None:
        """Defensively copy caller-owned iterables."""
        object.__setattr__(self, "risk_assessments", tuple(self.risk_assessments))
        object.__setattr__(self, "attack_chains", tuple(self.attack_chains))
        object.__setattr__(self, "correlations", tuple(self.correlations))

    def to_dict(self) -> dict[str, Any]:
        """Serialize snapshot metadata and object references to plain data."""
        return {
            "risk_assessments": [item.to_dict() for item in self.risk_assessments],
            "attack_chains": [item.to_dict() for item in self.attack_chains],
            "correlations": [item.to_dict() for item in self.correlations],
            "finding_count": self.finding_count,
            "entity_count": self.entity_count,
            "resolved_entity_count": self.resolved_entity_count,
            "relationship_count": self.relationship_count,
            "snapshot_version": self.snapshot_version,
            "generated_at": self.generated_at,
        }
