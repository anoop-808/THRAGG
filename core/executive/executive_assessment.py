"""
core.executive_assessment
=========================

Milestone 8 executive assessment contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .framework_statistics import FrameworkStatistics
from .observation import Observation
from .security_posture import SecurityPosture
from ..shared.stable_id import stable_sha_id
from ..shared.traceability_map import TraceabilityMap

__all__ = ["ExecutiveAssessment", "stable_executive_assessment_id"]


def stable_executive_assessment_id(
    snapshot_version: str,
    snapshot_generated_at: str,
    engine_version: str,
) -> str:
    """Return a deterministic ExecutiveAssessment id."""
    return stable_sha_id(
        "exec",
        snapshot_version,
        snapshot_generated_at,
        engine_version,
    )


@dataclass(frozen=True)
class ExecutiveAssessment:
    """Structured executive intelligence output."""

    id: str
    summary: str
    observations: tuple[Observation, ...]
    recommendations: tuple[str, ...]
    statistics: FrameworkStatistics
    security_posture: SecurityPosture
    traceability: TraceabilityMap
    engine_version: str
    generated_at: str

    def __post_init__(self) -> None:
        """Defensively copy caller-owned iterables."""
        object.__setattr__(self, "observations", tuple(self.observations))
        object.__setattr__(self, "recommendations", tuple(self.recommendations))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain data without rendering a report."""
        return {
            "id": self.id,
            "summary": self.summary,
            "observations": [
                observation.to_dict() for observation in self.observations
            ],
            "recommendations": list(self.recommendations),
            "statistics": self.statistics.to_dict(),
            "security_posture": self.security_posture.value,
            "traceability": {
                "observation_to_risks": [
                    (key, list(items))
                    for key, items in self.traceability.observation_to_risks
                ],
                "observation_to_attack_chains": [
                    (key, list(items))
                    for key, items in self.traceability.observation_to_attack_chains
                ],
                "observation_to_correlations": [
                    (key, list(items))
                    for key, items in self.traceability.observation_to_correlations
                ],
                "recommendation_to_observations": [
                    (key, list(items))
                    for key, items in self.traceability.recommendation_to_observations
                ],
            },
            "engine_version": self.engine_version,
            "generated_at": self.generated_at,
        }
