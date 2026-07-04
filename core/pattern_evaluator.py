"""
core.pattern_evaluator
======================

Deterministic graph pattern matching for correlation rules.
"""

from __future__ import annotations

from dataclasses import dataclass

from .correlation_rule import Binding, CorrelationRule, RelationshipPattern
from .core_relationship_fact import RelationshipFact
from .finding import EntityType
from .knowledge_base import KnowledgeBase
from .resolved_entity import ResolvedEntity

__all__ = ["PatternMatch", "PatternEvaluator"]


@dataclass(frozen=True)
class PatternMatch:
    """Successful rule binding and its matched relationship facts."""

    bindings: Binding
    relationships: tuple[RelationshipFact, ...]


class PatternEvaluator:
    """Evaluate declarative relationship patterns against a KnowledgeBase."""

    def evaluate(
        self,
        rule: CorrelationRule,
        knowledge_base: KnowledgeBase,
        resolved_entities: dict[str, ResolvedEntity] | None = None,
    ) -> tuple[PatternMatch, ...]:
        """Return all bindings that satisfy a rule."""
        if not rule.patterns:
            return ()

        entity_index = resolved_entities or {}
        matches = (PatternMatch({}, ()),)

        for pattern in rule.patterns:
            matches = self._extend_matches(
                matches,
                pattern,
                knowledge_base,
                entity_index,
            )
            if not matches:
                return ()

        return tuple(
            match
            for match in matches
            if all(
                condition.evaluate(match.bindings, match.relationships)
                for condition in rule.conditions
            )
        )

    def _extend_matches(
        self,
        matches: tuple[PatternMatch, ...],
        pattern: RelationshipPattern,
        knowledge_base: KnowledgeBase,
        entity_index: dict[str, ResolvedEntity],
    ) -> tuple[PatternMatch, ...]:
        extended: list[PatternMatch] = []
        for match in matches:
            for relationship in knowledge_base.get_relationships():
                new_binding = self._bind(
                    match.bindings,
                    pattern,
                    relationship,
                    entity_index,
                )
                if new_binding is not None:
                    extended.append(
                        PatternMatch(new_binding, match.relationships + (relationship,))
                    )
        return tuple(extended)

    def _bind(
        self,
        bindings: Binding,
        pattern: RelationshipPattern,
        relationship: RelationshipFact,
        entity_index: dict[str, ResolvedEntity],
    ) -> Binding | None:
        if (
            relationship.source_entity_type is not pattern.source_entity_type
            or relationship.relationship_type is not pattern.relationship_type
            or relationship.target_entity_type is not pattern.target_entity_type
        ):
            return None

        new_bindings = dict(bindings)
        if not self._bind_entity(
            new_bindings,
            pattern.source_variable,
            relationship.source_entity_id,
            pattern.source_entity_type,
            entity_index,
        ):
            return None
        if not self._bind_entity(
            new_bindings,
            pattern.target_variable,
            relationship.target_entity_id,
            pattern.target_entity_type,
            entity_index,
        ):
            return None
        return new_bindings

    def _bind_entity(
        self,
        bindings: Binding,
        variable: str,
        entity_id: str,
        entity_type: EntityType,
        entity_index: dict[str, ResolvedEntity],
    ) -> bool:
        current = bindings.get(variable)
        if current is not None:
            return current.id == entity_id and current.entity_type is entity_type

        entity = entity_index.get(entity_id) or ResolvedEntity(
            id=entity_id,
            entity_type=entity_type,
            primary_identifier=entity_id,
        )
        if entity.entity_type is not entity_type:
            return False
        bindings[variable] = entity
        return True
