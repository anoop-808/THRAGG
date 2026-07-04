"""
core.correlation_rule
=====================

Declarative correlation rule objects for Milestone 5.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from ..foundation.finding import Confidence, EntityType, Severity
from ..foundation.core_relationship_fact import RelationshipFact, RelationshipType
from ..foundation.resolved_entity import ResolvedEntity

__all__ = [
    "Binding",
    "Condition",
    "EntityAttributeEqualsCondition",
    "RelationshipEvidenceEqualsCondition",
    "RelationshipPattern",
    "AttackStage",
    "CorrelationRule",
    "RuleRegistry",
    "correlation_rule_from_dict",
]

Binding = dict[str, ResolvedEntity]


class AttackStage(str, Enum):
    """Ordered attack stages used for timeline construction."""

    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"


class Condition(Protocol):
    """Serializable, inspectable condition contract."""

    def evaluate(
        self,
        bindings: Binding,
        relationships: tuple[RelationshipFact, ...],
    ) -> bool:
        """Return True when a binding satisfies this condition."""

    def to_dict(self) -> dict[str, object]:
        """Serialize this condition for audit output."""


@dataclass(frozen=True)
class EntityAttributeEqualsCondition:
    """Require one bound entity attribute to equal an expected value."""

    variable: str
    attribute: str
    expected: object

    def evaluate(
        self,
        bindings: Binding,
        relationships: tuple[RelationshipFact, ...],
    ) -> bool:
        entity = bindings.get(self.variable)
        return (
            entity is not None
            and entity.attributes.get(self.attribute) == self.expected
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "type": "EntityAttributeEqualsCondition",
            "variable": self.variable,
            "attribute": self.attribute,
            "expected": self.expected,
        }


@dataclass(frozen=True)
class RelationshipEvidenceEqualsCondition:
    """Require at least one matched relationship evidence value to match."""

    key: str
    expected: object
    source_variable: str | None = None
    target_variable: str | None = None

    def evaluate(
        self,
        bindings: Binding,
        relationships: tuple[RelationshipFact, ...],
    ) -> bool:
        return any(
            relationship.supporting_evidence.get(self.key) == self.expected
            and self._matches_endpoint(relationship, bindings)
            for relationship in relationships
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "type": "RelationshipEvidenceEqualsCondition",
            "key": self.key,
            "expected": self.expected,
            "source_variable": self.source_variable,
            "target_variable": self.target_variable,
        }

    def _matches_endpoint(
        self,
        relationship: RelationshipFact,
        bindings: Binding,
    ) -> bool:
        source = bindings.get(self.source_variable) if self.source_variable else None
        target = bindings.get(self.target_variable) if self.target_variable else None
        if source is not None and relationship.source_entity_id != source.id:
            return False
        if target is not None and relationship.target_entity_id != target.id:
            return False
        return True


@dataclass(frozen=True)
class RelationshipPattern:
    """Declarative graph relationship pattern with variable names."""

    source_variable: str
    source_entity_type: EntityType
    relationship_type: RelationshipType
    target_variable: str
    target_entity_type: EntityType

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RelationshipPattern":
        """Build a typed pattern from serialized rule data."""
        return cls(
            source_variable=str(data["source_variable"]),
            source_entity_type=EntityType(str(data["source_entity_type"]).upper()),
            relationship_type=RelationshipType(str(data["relationship_type"]).upper()),
            target_variable=str(data["target_variable"]),
            target_entity_type=EntityType(str(data["target_entity_type"]).upper()),
        )


@dataclass(frozen=True)
class CorrelationRule:
    """Deterministic graph query definition."""

    rule_id: str
    title: str
    description: str
    version: str
    severity: Severity
    confidence: Confidence
    mitre: tuple[str, ...]
    category: str
    tags: tuple[str, ...]
    recommendation: str
    patterns: tuple[RelationshipPattern, ...]
    stage: AttackStage = AttackStage.DISCOVERY
    conditions: tuple[Condition, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CorrelationRule":
        """Build a typed correlation rule from serialized rule data."""
        return correlation_rule_from_dict(data)


def correlation_rule_from_dict(data: dict[str, Any]) -> CorrelationRule:
    """Build a CorrelationRule from plain data loaded by any parser."""
    return CorrelationRule(
        rule_id=str(data["rule_id"]),
        title=str(data["title"]),
        description=str(data["description"]),
        version=str(data.get("version", "1.0")),
        severity=Severity(str(data.get("severity", Severity.LOW.value)).upper()),
        confidence=Confidence(
            str(data.get("confidence", Confidence.MEDIUM.value)).upper()
        ),
        mitre=tuple(str(item) for item in data.get("mitre", ())),
        category=str(data.get("category", "Correlation")),
        tags=tuple(str(item) for item in data.get("tags", ())),
        recommendation=str(data.get("recommendation", "Review supporting evidence.")),
        patterns=tuple(
            RelationshipPattern.from_dict(item) for item in data.get("patterns", ())
        ),
        stage=AttackStage(str(data.get("stage", AttackStage.DISCOVERY.value)).upper()),
        conditions=tuple(
            _condition_from_dict(item) for item in data.get("conditions", ())
        ),
    )


def _condition_from_dict(data: dict[str, Any]) -> Condition:
    condition_type = str(data["type"])
    if condition_type == "EntityAttributeEqualsCondition":
        return EntityAttributeEqualsCondition(
            variable=str(data["variable"]),
            attribute=str(data["attribute"]),
            expected=data.get("expected"),
        )
    if condition_type == "RelationshipEvidenceEqualsCondition":
        return RelationshipEvidenceEqualsCondition(
            key=str(data["key"]),
            expected=data.get("expected"),
            source_variable=data.get("source_variable"),
            target_variable=data.get("target_variable"),
        )
    raise ValueError(f"Unsupported correlation condition type: {condition_type}")


class RuleRegistry:
    """Deterministic store for built-in correlation rules."""

    def __init__(self) -> None:
        self._rules = tuple(sorted(_built_in_rules(), key=lambda rule: rule.rule_id))

    def get_rules(self) -> tuple[CorrelationRule, ...]:
        """Return built-in rules in deterministic order."""
        return self._rules

    def get_rule(self, rule_id: str) -> CorrelationRule | None:
        """Return one rule by id."""
        return next((rule for rule in self._rules if rule.rule_id == rule_id), None)


def _built_in_rules() -> tuple[CorrelationRule, ...]:
    return (
        CorrelationRule(
            rule_id="CORR-PUBLIC-SSH-PRIVILEGED-ACCOUNT",
            title="Public SSH host used by privileged account",
            description=(
                "A public host exposes SSH and a privileged account authenticated to it."
            ),
            version="1.0",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            mitre=("T1021.004",),
            category="Initial Access",
            tags=("ssh", "public-exposure", "privileged-account"),
            recommendation="Restrict public SSH access and review privileged logins.",
            stage=AttackStage.INITIAL_ACCESS,
            patterns=(
                RelationshipPattern(
                    "HOST",
                    EntityType.HOST,
                    RelationshipType.EXPOSES,
                    "SERVICE",
                    EntityType.SERVICE,
                ),
                RelationshipPattern(
                    "USER",
                    EntityType.USER,
                    RelationshipType.AUTHENTICATED_TO,
                    "HOST",
                    EntityType.HOST,
                ),
            ),
            conditions=(
                RelationshipEvidenceEqualsCondition("port", 22, "HOST", "SERVICE"),
                EntityAttributeEqualsCondition("HOST", "public", True),
                EntityAttributeEqualsCondition("USER", "privileged", True),
            ),
        ),
        CorrelationRule(
            rule_id="CORR-PUBLIC-STORAGE-SENSITIVE-DATA",
            title="Public storage containing sensitive data",
            description="A public storage resource is marked as containing sensitive data.",
            version="1.0",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            mitre=("T1530",),
            category="Data Exposure",
            tags=("storage", "public-exposure", "sensitive-data"),
            recommendation="Remove public access and verify data classification.",
            stage=AttackStage.COLLECTION,
            patterns=(
                RelationshipPattern(
                    "CLOUD",
                    EntityType.CLOUD_RESOURCE,
                    RelationshipType.OWNS,
                    "STORAGE",
                    EntityType.STORAGE,
                ),
            ),
            conditions=(
                EntityAttributeEqualsCondition("STORAGE", "public", True),
                EntityAttributeEqualsCondition("STORAGE", "sensitive_data", True),
            ),
        ),
        CorrelationRule(
            rule_id="CORR-ADMIN-AUTH-EXPOSED-SYSTEM",
            title="Administrative account authenticating to exposed system",
            description="An administrative account authenticated to an exposed host.",
            version="1.0",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            mitre=("T1078",),
            category="Identity Exposure",
            tags=("admin", "authentication", "exposed-system"),
            recommendation="Review administrative access to exposed systems.",
            stage=AttackStage.LATERAL_MOVEMENT,
            patterns=(
                RelationshipPattern(
                    "ADMIN",
                    EntityType.USER,
                    RelationshipType.AUTHENTICATED_TO,
                    "HOST",
                    EntityType.HOST,
                ),
                RelationshipPattern(
                    "HOST",
                    EntityType.HOST,
                    RelationshipType.EXPOSES,
                    "SERVICE",
                    EntityType.SERVICE,
                ),
            ),
            conditions=(
                EntityAttributeEqualsCondition("ADMIN", "admin", True),
                EntityAttributeEqualsCondition("HOST", "public", True),
            ),
        ),
    )
