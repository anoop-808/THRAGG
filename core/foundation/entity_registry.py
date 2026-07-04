"""
Central entity registry for correlation foundation.

The registry owns canonical ResolvedEntity objects and delegates identity
deduplication to the existing IdentityResolver.
"""

from __future__ import annotations

from collections.abc import Iterable

from .entity import Entity
from .identity_resolver import IdentityResolver
from .resolved_entity import ResolvedEntity

__all__ = ["EntityRegistry", "EntityRepository"]


class EntityRepository:
    """In-memory repository for canonical entities."""

    def __init__(self) -> None:
        self._entities: dict[str, ResolvedEntity] = {}

    def add(self, entity: ResolvedEntity) -> bool:
        """Store an entity, returning False for duplicates."""
        if entity.id in self._entities:
            return False
        self._entities[entity.id] = entity
        return True

    def get(self, entity_id: str) -> ResolvedEntity | None:
        """Return one entity by id."""
        return self._entities.get(entity_id)

    def list(self) -> tuple[ResolvedEntity, ...]:
        """Return entities in deterministic id order."""
        return tuple(self._entities[item_id] for item_id in sorted(self._entities))

    def by_finding(self, finding_id: str) -> tuple[ResolvedEntity, ...]:
        """Return entities supported by one finding."""
        return tuple(
            entity for entity in self.list() if finding_id in entity.source_findings
        )

    def as_dict(self) -> dict[str, ResolvedEntity]:
        """Return a shallow id index for rule evaluators."""
        return dict(self._entities)


class EntityRegistry:
    """Resolve duplicate extracted entities before graph construction."""

    def __init__(self, repository: EntityRepository | None = None) -> None:
        self.repository = repository or EntityRepository()
        self._source_entities: list[Entity] = []

    def register(self, entities: Iterable[Entity]) -> tuple[ResolvedEntity, ...]:
        """Resolve and store extracted entities."""
        self._source_entities = list(entities)
        resolved = IdentityResolver.resolve(self._source_entities)
        self.repository = EntityRepository()
        for entity in resolved:
            self.repository.add(entity)
        return self.repository.list()

    def merge(self, entities: Iterable[Entity]) -> tuple[ResolvedEntity, ...]:
        """Merge additional extracted entities with the current registry."""
        return self.register([*self._source_entities, *entities])
