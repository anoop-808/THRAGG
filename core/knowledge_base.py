"""
core.knowledge_base
===================

Validated relationship repository for THRAGG.

The KnowledgeBase is the source of truth for relationship knowledge.  It stores
only RelationshipFact objects that pass the existing relationship validator and
never mutates the facts it receives.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING

from .core_relationship_fact import RelationshipFact
from .core_relationship_validator import RelationshipValidator

__all__ = ["KnowledgeBase"]

if TYPE_CHECKING:
    from .relationship_graph import RelationshipGraph


class KnowledgeBase:
    """Indexed repository of validated RelationshipFact objects.

    Example:
        kb = KnowledgeBase()
        kb.add_relationship(relationship)
        kb.get_relationships_between("resolved-host-1", "resolved-service-1")
    """

    def __init__(self) -> None:
        self._relationships: dict[str, RelationshipFact] = {}
        self._by_entity: dict[str, set[str]] = {}

    # Public API

    @property
    def relationship_count(self) -> int:
        """Number of validated relationships owned by this source of truth."""
        return len(self._relationships)

    @property
    def entity_count(self) -> int:
        """Number of entity ids indexed by stored relationships."""
        return len(self._by_entity)

    def add_relationship(self, relationship: object) -> bool:
        """Store a validated relationship, returning False when rejected."""
        if not isinstance(relationship, RelationshipFact):
            return False
        if relationship.id in self._relationships:
            return False
        if not RelationshipValidator.is_valid(relationship):
            return False

        self._relationships[relationship.id] = relationship
        self._by_entity.setdefault(relationship.source_entity_id, set()).add(
            relationship.id
        )
        self._by_entity.setdefault(relationship.target_entity_id, set()).add(
            relationship.id
        )
        return True

    def add_relationships(
        self, relationships: Iterable[object]
    ) -> tuple[RelationshipFact, ...]:
        """Store valid relationships from an iterable and return accepted facts."""
        accepted: list[RelationshipFact] = []
        for relationship in relationships:
            if self.add_relationship(relationship):
                accepted.append(relationship)
        return tuple(accepted)

    def remove_relationship(self, relationship_id: str) -> bool:
        """Remove a relationship by id, returning False when absent."""
        relationship = self._relationships.pop(relationship_id, None)
        if relationship is None:
            return False

        self._discard_entity_index(relationship.source_entity_id, relationship_id)
        self._discard_entity_index(relationship.target_entity_id, relationship_id)
        return True

    def get_relationship(self, relationship_id: str) -> RelationshipFact | None:
        """Return one relationship by id, or None when absent."""
        return self._relationships.get(relationship_id)

    def get_relationships(
        self, entity_id: str | None = None
    ) -> tuple[RelationshipFact, ...]:
        """Return all relationships, or all relationships attached to an entity."""
        if entity_id is None:
            ids = self._relationships
        else:
            ids = self._by_entity.get(entity_id, set())
        # Deterministic guarantee: relationship reads are ordered by stable id.
        return tuple(self._relationships[item_id] for item_id in sorted(ids))

    def get_relationships_between(
        self, source_entity_id: str, target_entity_id: str
    ) -> tuple[RelationshipFact, ...]:
        """Return directed relationships from source to target.

        Example:
            kb.get_relationships_between("resolved-host-1", "resolved-service-1")
        """
        return tuple(
            relationship
            for relationship in self.get_relationships(source_entity_id)
            if relationship.source_entity_id == source_entity_id
            and relationship.target_entity_id == target_entity_id
        )

    def get_neighbors(self, entity_id: str) -> tuple[str, ...]:
        """Return deterministic neighboring entity ids for one entity."""
        neighbors: set[str] = set()
        for relationship in self.get_relationships(entity_id):
            if relationship.source_entity_id == entity_id:
                neighbors.add(relationship.target_entity_id)
            if relationship.target_entity_id == entity_id:
                neighbors.add(relationship.source_entity_id)
        # Deterministic guarantee: neighbor ids are sorted for repeatable output.
        return tuple(sorted(neighbors))

    def relationship_exists(self, relationship_id: str) -> bool:
        """Return True when a relationship id is stored."""
        return relationship_id in self._relationships

    def has_relationship_between(
        self, source_entity_id: str, target_entity_id: str
    ) -> bool:
        """Return True when any directed relationship exists between two ids."""
        return bool(
            self.get_relationships_between(source_entity_id, target_entity_id)
        )

    def build_graph(self) -> RelationshipGraph:
        """Generate a lightweight traversal graph from stored relationships.

        Ownership: KnowledgeBase remains the source of truth.  The generated
        graph only references the stored RelationshipFact objects.
        """
        from .relationship_graph import RelationshipGraph

        return RelationshipGraph.from_knowledge_base(self)

    def __iter__(self) -> Iterator[RelationshipFact]:
        """Iterate stored relationships in deterministic id order."""
        return iter(self.get_relationships())

    def __len__(self) -> int:
        """Return the number of stored relationships."""
        return len(self._relationships)

    # Internal helpers

    def _discard_entity_index(self, entity_id: str, relationship_id: str) -> None:
        ids = self._by_entity.get(entity_id)
        if ids is None:
            return
        ids.discard(relationship_id)
        if not ids:
            del self._by_entity[entity_id]
