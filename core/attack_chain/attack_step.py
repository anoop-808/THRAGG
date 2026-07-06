"""
core.attack_step
================

Step object used by dashboard and executive intelligence consumers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..foundation.finding import Confidence

__all__ = ["AttackStep"]


@dataclass(frozen=True)
class AttackStep:
    """One attacker action in an attack narrative."""

    step_number: int = 0
    technique: str = ""
    mitre_id: str = ""
    entity: str = ""
    evidence: tuple[str, ...] = ()
    description: str = ""
    confidence: Confidence = Confidence.LOW
    step_id: str = ""
    order: int = 0
    correlation_id: str = ""
    stage: str = ""
    entities: tuple[str, ...] = ()
    relationships: tuple[str, ...] = ()
    supporting_findings: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        evidence = tuple(self.evidence or self.supporting_findings)
        mitre_techniques = tuple(self.mitre_techniques or ((self.mitre_id,) if self.mitre_id else ()))
        step_number = self.step_number or self.order
        order = self.order or step_number
        technique = self.technique or self.stage
        mitre_id = self.mitre_id or (mitre_techniques[0] if mitre_techniques else "")
        entity = self.entity or (self.entities[0] if self.entities else "")

        object.__setattr__(self, "step_number", step_number)
        object.__setattr__(self, "order", order)
        object.__setattr__(self, "technique", technique)
        object.__setattr__(self, "mitre_id", mitre_id)
        object.__setattr__(self, "entity", entity)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "entities", tuple(self.entities))
        object.__setattr__(self, "relationships", tuple(self.relationships))
        object.__setattr__(self, "supporting_findings", tuple(self.supporting_findings or evidence))
        object.__setattr__(self, "mitre_techniques", mitre_techniques or ((mitre_id,) if mitre_id else ()))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dashboard-ready plain data."""
        return {
            "step_number": self.step_number,
            "technique": self.technique,
            "mitre_id": self.mitre_id,
            "entity": self.entity,
            "evidence": list(self.evidence),
            "confidence": self.confidence.value,
            "step_id": self.step_id,
            "order": self.order,
            "correlation_id": self.correlation_id,
            "stage": self.stage,
            "description": self.description,
            "entities": list(self.entities),
            "relationships": list(self.relationships),
            "supporting_findings": list(self.supporting_findings),
            "mitre_techniques": list(self.mitre_techniques),
        }
