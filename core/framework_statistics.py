"""
core.framework_statistics
=========================

Typed Milestone 8 framework statistics contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["CountMetric", "FrameworkStatistics"]


@dataclass(frozen=True)
class CountMetric:
    """Named count used for deterministic top-N statistics."""

    name: str
    count: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain data."""
        return {"name": self.name, "count": self.count}


@dataclass(frozen=True)
class FrameworkStatistics:
    """Typed aggregate statistics for an ExecutiveAssessment."""

    total_findings: int
    total_entities: int
    total_relationships: int
    total_correlations: int
    total_attack_chains: int
    risk_counts: tuple[CountMetric, ...]
    top_entity_types: tuple[CountMetric, ...]
    top_attack_stages: tuple[CountMetric, ...]
    top_attack_categories: tuple[CountMetric, ...]

    def __post_init__(self) -> None:
        """Defensively copy caller-owned iterables."""
        object.__setattr__(self, "risk_counts", tuple(self.risk_counts))
        object.__setattr__(self, "top_entity_types", tuple(self.top_entity_types))
        object.__setattr__(self, "top_attack_stages", tuple(self.top_attack_stages))
        object.__setattr__(
            self,
            "top_attack_categories",
            tuple(self.top_attack_categories),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain data."""
        return {
            "total_findings": self.total_findings,
            "total_entities": self.total_entities,
            "total_relationships": self.total_relationships,
            "total_correlations": self.total_correlations,
            "total_attack_chains": self.total_attack_chains,
            "risk_counts": [item.to_dict() for item in self.risk_counts],
            "top_entity_types": [item.to_dict() for item in self.top_entity_types],
            "top_attack_stages": [item.to_dict() for item in self.top_attack_stages],
            "top_attack_categories": [
                item.to_dict() for item in self.top_attack_categories
            ],
        }

    @property
    def risk_info_count(self) -> int:
        """Backward-compatible read access for existing callers."""
        return self._risk_count("INFO")

    @property
    def risk_low_count(self) -> int:
        """Backward-compatible read access for existing callers."""
        return self._risk_count("LOW")

    @property
    def risk_medium_count(self) -> int:
        """Backward-compatible read access for existing callers."""
        return self._risk_count("MEDIUM")

    @property
    def risk_high_count(self) -> int:
        """Backward-compatible read access for existing callers."""
        return self._risk_count("HIGH")

    @property
    def risk_critical_count(self) -> int:
        """Backward-compatible read access for existing callers."""
        return self._risk_count("CRITICAL")

    def _risk_count(self, name: str) -> int:
        return next(
            (item.count for item in self.risk_counts if item.name == name),
            0,
        )
