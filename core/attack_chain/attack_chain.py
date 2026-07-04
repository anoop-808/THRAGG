"""
core.attack_chain
=================

Public AttackChain object for THRAGG Milestone 6.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .chain_edge import ChainEdge
from ..foundation.finding import Confidence, Severity

__all__ = ["AttackChain"]


@dataclass(frozen=True)
class AttackChain:
    """Deterministic chain of connected Correlation objects."""

    id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    entry_point: str
    target: str
    timeline: tuple[dict[str, str], ...]
    correlations: tuple[str, ...]
    chain_edges: tuple[ChainEdge, ...]
    entities: tuple[str, ...]
    relationships: tuple[str, ...]
    supporting_findings: tuple[str, ...]
    recommendations: tuple[str, ...]
    created_at: str

    def __post_init__(self) -> None:
        """Defensively copy caller-owned mutable values."""
        object.__setattr__(self, "timeline", tuple(dict(item) for item in self.timeline))
        object.__setattr__(self, "correlations", tuple(self.correlations))
        object.__setattr__(self, "chain_edges", tuple(self.chain_edges))
        object.__setattr__(self, "entities", tuple(self.entities))
        object.__setattr__(self, "relationships", tuple(self.relationships))
        object.__setattr__(
            self,
            "supporting_findings",
            tuple(self.supporting_findings),
        )
        object.__setattr__(self, "recommendations", tuple(self.recommendations))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary suitable for JSON output."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "entry_point": self.entry_point,
            "target": self.target,
            "timeline": [dict(item) for item in self.timeline],
            "correlations": list(self.correlations),
            "chain_edges": [edge.to_dict() for edge in self.chain_edges],
            "entities": list(self.entities),
            "relationships": list(self.relationships),
            "supporting_findings": list(self.supporting_findings),
            "recommendations": list(self.recommendations),
            "created_at": self.created_at,
        }
