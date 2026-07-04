"""Relationship repository for correlation foundation."""

from __future__ import annotations

from collections.abc import Iterable

from .core_relationship_fact import RelationshipFact
from .knowledge_base import KnowledgeBase

__all__ = ["RelationshipRepository"]


class RelationshipRepository:
    """In-memory store for validated relationships."""

    def __init__(self, knowledge_base: KnowledgeBase | None = None) -> None:
        self.knowledge_base = knowledge_base or KnowledgeBase()

    def add(self, relationship: RelationshipFact) -> bool:
        """Store one relationship."""
        return self.knowledge_base.add_relationship(relationship)

    def add_many(
        self, relationships: Iterable[RelationshipFact]
    ) -> tuple[RelationshipFact, ...]:
        """Store many relationships and return accepted facts."""
        return self.knowledge_base.add_relationships(relationships)

    def list(self) -> tuple[RelationshipFact, ...]:
        """Return relationships in deterministic order."""
        return self.knowledge_base.get_relationships()
