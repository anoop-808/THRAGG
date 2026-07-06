"""
core.attack_template
====================

Frozen attack-chain template contract.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..foundation.finding import Severity

__all__ = ["AttackTemplate"]


@dataclass(frozen=True)
class AttackTemplate:
    """Declarative template schema shared by all attack-chain templates."""

    id: str
    name: str
    description: str
    mitre_chain: tuple[str, ...]
    required_entities: tuple[str, ...]
    required_findings: tuple[str, ...]
    entry_point_type: str
    confidence_base: float
    severity: Severity
    tags: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "mitre_chain", tuple(self.mitre_chain))
        object.__setattr__(self, "required_entities", tuple(self.required_entities))
        object.__setattr__(self, "required_findings", tuple(self.required_findings))
        object.__setattr__(self, "tags", tuple(self.tags))

    def to_dict(self) -> dict[str, object]:
        """Serialize to plain data."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "mitre_chain": list(self.mitre_chain),
            "required_entities": list(self.required_entities),
            "required_findings": list(self.required_findings),
            "entry_point_type": self.entry_point_type,
            "confidence_base": self.confidence_base,
            "severity": self.severity.value,
            "tags": list(self.tags),
        }
