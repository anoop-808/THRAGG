"""Data-driven relationship inference from validated Finding objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .core_relationship_fact import (
    RelationshipFact,
    RelationshipType,
    stable_relationship_fact_id,
)
from .finding import Confidence, EntityType, Finding
from .resolved_entity import ResolvedEntity

__all__ = [
    "RelationshipInferenceRule",
    "RelationshipInferencer",
    "example_relationship_rules",
    "relationship_inference_rule_from_dict",
]


@dataclass(frozen=True)
class RelationshipInferenceRule:
    """Declarative rule for linking entities extracted from the same finding."""

    rule_id: str
    source_entity_type: EntityType
    relationship_type: RelationshipType
    target_entity_type: EntityType
    required_evidence_keys: tuple[str, ...] = field(default_factory=tuple)
    confidence: Confidence = Confidence.MEDIUM

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RelationshipInferenceRule":
        """Build a typed inference rule from serialized rule data."""
        return relationship_inference_rule_from_dict(data)


def relationship_inference_rule_from_dict(
    data: dict[str, Any]
) -> RelationshipInferenceRule:
    """Build a RelationshipInferenceRule from plain data loaded by any parser."""
    return RelationshipInferenceRule(
        rule_id=str(data["rule_id"]),
        source_entity_type=EntityType(str(data["source_entity_type"]).upper()),
        relationship_type=RelationshipType(str(data["relationship_type"]).upper()),
        target_entity_type=EntityType(str(data["target_entity_type"]).upper()),
        required_evidence_keys=tuple(
            str(item) for item in data.get("required_evidence_keys", ())
        ),
        confidence=Confidence(
            str(data.get("confidence", Confidence.MEDIUM.value)).upper()
        ),
    )


def example_relationship_rules() -> tuple[RelationshipInferenceRule, ...]:
    """Return starter rules; callers can replace this list with loaded data."""
    return (
        RelationshipInferenceRule(
            "REL-HOST-EXPOSES-SERVICE",
            EntityType.HOST,
            RelationshipType.EXPOSES,
            EntityType.SERVICE,
            ("port",),
            Confidence.HIGH,
        ),
        RelationshipInferenceRule(
            "REL-USER-AUTHENTICATED-TO-HOST",
            EntityType.USER,
            RelationshipType.AUTHENTICATED_TO,
            EntityType.HOST,
            (),
            Confidence.MEDIUM,
        ),
        RelationshipInferenceRule(
            "REL-HOST-RELATED-CLOUD",
            EntityType.HOST,
            RelationshipType.RELATED_TO,
            EntityType.CLOUD_RESOURCE,
            (),
            Confidence.MEDIUM,
        ),
        RelationshipInferenceRule(
            "REL-IDENTITY-RELATED-TO-IDENTITY",
            EntityType.IDENTITY,
            RelationshipType.RELATED_TO,
            EntityType.IDENTITY,
            (),
            Confidence.HIGH,
        ),
        RelationshipInferenceRule(
            "REL-IDENTITY-RELATED-CLOUD",
            EntityType.IDENTITY,
            RelationshipType.RELATED_TO,
            EntityType.CLOUD_RESOURCE,
            (),
            Confidence.HIGH,
        ),
        RelationshipInferenceRule(
            "REL-CLOUD-RELATED-USER",
            EntityType.CLOUD_RESOURCE,
            RelationshipType.RELATED_TO,
            EntityType.USER,
            (),
            Confidence.HIGH,
        ),
    )


class RelationshipInferencer:
    """Infer graph edges from resolved entities and validated findings."""

    def __init__(
        self, rules: tuple[RelationshipInferenceRule, ...] | None = None
    ) -> None:
        self.rules = rules or example_relationship_rules()

    def infer(
        self,
        findings: tuple[Finding, ...],
        entities: tuple[ResolvedEntity, ...],
    ) -> tuple[RelationshipFact, ...]:
        """Infer relationships without reading raw evidence formats."""
        by_finding: dict[str, list[ResolvedEntity]] = {}
        for entity in entities:
            for finding_id in entity.source_findings:
                by_finding.setdefault(finding_id, []).append(entity)

        relationships: list[RelationshipFact] = []
        for finding in findings:
            candidates = by_finding.get(finding.id, [])
            for rule in self.rules:
                if not all(key in finding.evidence for key in rule.required_evidence_keys):
                    continue
                sources = [e for e in candidates if e.entity_type is rule.source_entity_type]
                targets = [e for e in candidates if e.entity_type is rule.target_entity_type]
                for source in sources:
                    for target in targets:
                        if source.id == target.id:
                            continue
                        relationships.append(self._build(rule, finding, source, target))
        return tuple(relationships)

    @staticmethod
    def _build(
        rule: RelationshipInferenceRule,
        finding: Finding,
        source: ResolvedEntity,
        target: ResolvedEntity,
    ) -> RelationshipFact:
        relationship_id = stable_relationship_fact_id(
            source.id,
            target.id,
            rule.relationship_type,
            finding.source_module,
            rule.rule_id,
        )
        return RelationshipFact(
            id=relationship_id,
            source_entity_id=source.id,
            source_entity_type=source.entity_type,
            target_entity_id=target.id,
            target_entity_type=target.entity_type,
            relationship_type=rule.relationship_type,
            source_module=finding.source_module,
            source_rule=rule.rule_id,
            confidence=rule.confidence,
            supporting_findings=(finding.id,),
            supporting_evidence=dict(finding.evidence),
            confidence_contribution=1.0,
            observed_at=finding.observed_at,
        )
