"""
core.traceability_map
=====================

Milestone 8 traceability contract.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["TraceabilityMap"]


@dataclass(frozen=True)
class TraceabilityMap:
    """Tuple-only mappings between M8 executive objects and source objects."""

    observation_to_risks: tuple[tuple[str, tuple[str, ...]], ...]
    observation_to_attack_chains: tuple[tuple[str, tuple[str, ...]], ...]
    observation_to_correlations: tuple[tuple[str, tuple[str, ...]], ...]
    recommendation_to_observations: tuple[tuple[str, tuple[str, ...]], ...]

    def __post_init__(self) -> None:
        """Defensively copy nested caller-owned iterables."""
        object.__setattr__(
            self,
            "observation_to_risks",
            _tuple_map(self.observation_to_risks),
        )
        object.__setattr__(
            self,
            "observation_to_attack_chains",
            _tuple_map(self.observation_to_attack_chains),
        )
        object.__setattr__(
            self,
            "observation_to_correlations",
            _tuple_map(self.observation_to_correlations),
        )
        object.__setattr__(
            self,
            "recommendation_to_observations",
            _tuple_map(self.recommendation_to_observations),
        )


def _tuple_map(
    value: tuple[tuple[str, tuple[str, ...]], ...],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    return tuple((key, tuple(items)) for key, items in value)
