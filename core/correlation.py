"""
core.correlation
================

Public Correlation object for THRAGG Milestone 5.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .finding import Confidence, Severity

__all__ = ["Correlation"]


@dataclass(frozen=True)
class Correlation:
    """One deterministic, explainable graph-rule match."""

    id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    recommendation: str
    mitre: tuple[str, ...]
    category: str
    tags: tuple[str, ...]
    timestamp: str
    matched_entities: tuple[dict[str, Any], ...]
    matched_relationships: tuple[str, ...]
    supporting_findings: tuple[str, ...]
    correlation_explanation: dict[str, Any]
    is_duplicate: bool = False

    def __post_init__(self) -> None:
        """Defensively copy caller-owned mutable values."""
        object.__setattr__(self, "mitre", tuple(self.mitre))
        object.__setattr__(self, "tags", tuple(self.tags))
        object.__setattr__(
            self,
            "matched_entities",
            tuple(dict(entity) for entity in self.matched_entities),
        )
        object.__setattr__(
            self,
            "matched_relationships",
            tuple(self.matched_relationships),
        )
        object.__setattr__(
            self,
            "supporting_findings",
            tuple(self.supporting_findings),
        )
        object.__setattr__(
            self,
            "correlation_explanation",
            dict(self.correlation_explanation),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary suitable for JSON output."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "recommendation": self.recommendation,
            "mitre": list(self.mitre),
            "category": self.category,
            "tags": list(self.tags),
            "timestamp": self.timestamp,
            "matched_entities": [dict(entity) for entity in self.matched_entities],
            "matched_relationships": list(self.matched_relationships),
            "supporting_findings": list(self.supporting_findings),
            "correlation_explanation": dict(self.correlation_explanation),
            "is_duplicate": self.is_duplicate,
        }
