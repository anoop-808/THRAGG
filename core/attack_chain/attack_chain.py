"""
core.attack_chain
=================

Public AttackChain object for THRAGG Milestone 6.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .attack_step import AttackStep
from .chain_edge import ChainEdge
from ..foundation.finding import Confidence, Severity

__all__ = ["AttackChain"]


@dataclass(frozen=True)
class AttackChain:
    """Immutable attack-chain foundation object."""

    chain_id: str = ""
    entry_point: str = ""
    steps: tuple[AttackStep, ...] = ()
    participating_entities: tuple[str, ...] = ()
    participating_relationships: tuple[str, ...] = ()
    supporting_findings: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    confidence: Confidence = Confidence.LOW
    severity: Severity = Severity.LOW
    description: str = ""
    template_id: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)
    id: str = ""
    title: str = ""
    target: str = ""
    timeline: tuple[dict[str, Any], ...] = ()
    correlations: tuple[str, ...] = ()
    chain_edges: tuple[ChainEdge, ...] = ()
    entities: tuple[str, ...] = ()
    relationships: tuple[str, ...] = ()
    recommendations: tuple[str, ...] = ()
    created_at: str = ""

    def __post_init__(self) -> None:
        """Defensively copy caller-owned mutable values."""
        chain_id = self.chain_id or self.id
        steps = tuple(self.steps) or self._steps_from_timeline(chain_id)
        entities = tuple(self.participating_entities or self.entities)
        relationships = tuple(self.participating_relationships or self.relationships)
        mitre = tuple(self.mitre_techniques) or tuple(
            dict.fromkeys(
                technique
                for step in steps
                for technique in ((step.mitre_id,) if step.mitre_id else step.mitre_techniques)
                if technique
            )
        )

        object.__setattr__(self, "chain_id", chain_id)
        object.__setattr__(self, "id", self.id or chain_id)
        object.__setattr__(self, "steps", steps)
        object.__setattr__(self, "participating_entities", entities)
        object.__setattr__(self, "participating_relationships", relationships)
        object.__setattr__(self, "mitre_techniques", mitre)
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))
        object.__setattr__(
            self,
            "timeline",
            tuple(MappingProxyType(dict(item)) for item in self.timeline),
        )
        object.__setattr__(self, "correlations", tuple(self.correlations))
        object.__setattr__(self, "chain_edges", tuple(self.chain_edges))
        object.__setattr__(self, "entities", tuple(self.entities or entities))
        object.__setattr__(self, "relationships", tuple(self.relationships or relationships))
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
            "chain_id": self.chain_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "entry_point": self.entry_point,
            "target": self.target,
            "ordered_steps": [step.to_dict() for step in self.steps],
            "steps": [step.to_dict() for step in self.steps],
            "timeline": [dict(item) for item in self.timeline],
            "correlations": list(self.correlations),
            "chain_edges": [edge.to_dict() for edge in self.chain_edges],
            "entities": list(self.entities),
            "participating_entities": list(self.entities),
            "relationships": list(self.relationships),
            "participating_relationships": list(self.relationships),
            "supporting_findings": list(self.supporting_findings),
            "mitre_techniques": list(self.mitre_techniques),
            "template_id": self.template_id,
            "metadata": dict(self.metadata),
            "recommendations": list(self.recommendations),
            "created_at": self.created_at,
        }

    def _steps_from_timeline(self, chain_id: str) -> tuple[AttackStep, ...]:
        """Return ordered narrative steps without changing the M6 constructor."""
        return tuple(
            AttackStep(
                step_id=f"{chain_id}-step-{index}",
                step_number=index,
                order=index,
                technique=str(item.get("technique", item.get("stage", ""))),
                mitre_id=str(item.get("mitre_id", next(iter(item.get("mitre", ())), ""))),
                entity=str(item.get("entity", next(iter(item.get("entities", ())), ""))),
                evidence=tuple(str(value) for value in item.get("evidence", item.get("supporting_findings", self.supporting_findings))),
                correlation_id=str(item.get("correlation_id", "")),
                stage=str(item.get("stage", "DISCOVERY")),
                description=str(item.get("description", item.get("stage", "DISCOVERY"))),
                entities=tuple(str(value) for value in item.get("entities", ())),
                relationships=tuple(
                    str(value) for value in item.get("relationships", ())
                ),
                supporting_findings=tuple(
                    str(value) for value in item.get("supporting_findings", ())
                ),
                mitre_techniques=tuple(str(value) for value in item.get("mitre", ())),
            )
            for index, item in enumerate(self.timeline, start=1)
        )
