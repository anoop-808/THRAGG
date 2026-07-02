"""
core.identity_resolver

Deterministic identity resolution for extracted Entity objects.

Consumes Entities and creates new ResolvedEntity objects. It never mutates
input Entities and performs no correlation, graph building, or scoring.
"""

from __future__ import annotations

from datetime import datetime, timezone
import ipaddress

from .entity import Entity
from .entity_schema import EntityValidationError, validate_entity
from .finding import EntityType
from .resolution_schema import validate_resolved_entity
from .resolved_entity import (
    ResolutionConfidence,
    ResolutionMethod,
    ResolutionRecord,
    ResolvedEntity,
    stable_resolved_entity_id,
)

RESOLVER_VERSION = "1.0.0"


class IdentityResolver:
    """Resolve extracted Entities into canonical identities."""

    @classmethod
    def resolve(cls, entities: list[Entity]) -> list[ResolvedEntity]:
        """Resolve a list of Entities into deterministic ResolvedEntities."""
        resolved: list[ResolvedEntity] = []
        indexes: dict[tuple[str, EntityType, str], ResolvedEntity] = {}

        for entity in entities:
            if not isinstance(entity, Entity):
                raise EntityValidationError(
                    f"IdentityResolver expected Entity objects, got {entity!r}"
                )
            validate_entity(entity)

        for entity in sorted(
            entities, key=lambda e: (e.type.value, e.primary_identifier, e.id)
        ):
            match, method, token = cls._find_match(entity, indexes)
            if match is None:
                match = cls._from_entity(entity)
                resolved.append(match)
            else:
                cls._merge(match, entity, method, token)
            cls._index(match, indexes)

        return sorted(resolved, key=lambda item: item.id)

    @classmethod
    def _find_match(
        cls,
        entity: Entity,
        indexes: dict[tuple[str, EntityType, str], ResolvedEntity],
    ) -> tuple[ResolvedEntity | None, ResolutionMethod, str]:
        identifiers = cls._identifier_tokens(entity)
        alias_tokens = cls._alias_tokens(entity)
        ip_tokens = cls._ip_tokens(entity)
        hostname_tokens = cls._hostname_tokens(entity)

        for token in identifiers:
            match = indexes.get(("primary", entity.type, token))
            if match is not None:
                return match, ResolutionMethod.EXACT_IDENTIFIER, token
        for token in alias_tokens:
            match = indexes.get(("alias", entity.type, token)) or indexes.get(
                ("primary", entity.type, token)
            )
            if match is not None:
                return match, ResolutionMethod.EXACT_ALIAS, token
        for token in ip_tokens:
            match = indexes.get(("ip", entity.type, token))
            if match is not None:
                return match, ResolutionMethod.EXACT_IP, token
        for token in hostname_tokens:
            match = indexes.get(("hostname", entity.type, token))
            if match is not None:
                return match, ResolutionMethod.EXACT_HOSTNAME, token
        return None, ResolutionMethod.UNKNOWN, ""

    @classmethod
    def _from_entity(cls, entity: Entity) -> ResolvedEntity:
        resolved_entity = ResolvedEntity(
            id=stable_resolved_entity_id(entity.type, entity.primary_identifier),
            entity_type=entity.type,
            primary_identifier=entity.primary_identifier,
            aliases=cls._aliases(entity.primary_identifier, entity.aliases),
            source_entities=[entity.id],
            source_findings=[entity.source_finding],
            source_modules=[entity.source_module],
            attributes=dict(entity.attributes),
            resolution_records=[],
        )
        validate_resolved_entity(resolved_entity)
        return resolved_entity

    @classmethod
    def _merge(
        cls,
        resolved_entity: ResolvedEntity,
        entity: Entity,
        method: ResolutionMethod,
        token: str,
    ) -> None:
        resolved_entity.aliases = cls._aliases(
            resolved_entity.primary_identifier,
            [
                *resolved_entity.aliases,
                entity.primary_identifier,
                *entity.aliases,
            ],
        )
        resolved_entity.source_entities = cls._unique_sorted(
            [*resolved_entity.source_entities, entity.id]
        )
        resolved_entity.source_findings = cls._unique_sorted(
            [*resolved_entity.source_findings, entity.source_finding]
        )
        resolved_entity.source_modules = cls._unique_sorted(
            [*resolved_entity.source_modules, entity.source_module]
        )
        resolved_entity.attributes = {**resolved_entity.attributes, **entity.attributes}
        resolved_entity.resolution_records.append(
            cls._record(method, token, resolved_entity, entity)
        )
        validate_resolved_entity(resolved_entity)

    @classmethod
    def _index(
        cls,
        resolved_entity: ResolvedEntity,
        indexes: dict[tuple[str, EntityType, str], ResolvedEntity],
    ) -> None:
        for token in cls._identifier_tokens(resolved_entity):
            indexes[("primary", resolved_entity.entity_type, token)] = resolved_entity
        for token in cls._alias_tokens(resolved_entity):
            indexes[("alias", resolved_entity.entity_type, token)] = resolved_entity
        for token in cls._ip_tokens(resolved_entity):
            indexes[("ip", resolved_entity.entity_type, token)] = resolved_entity
        for token in cls._hostname_tokens(resolved_entity):
            indexes[("hostname", resolved_entity.entity_type, token)] = resolved_entity

    @staticmethod
    def _record(
        method: ResolutionMethod,
        token: str,
        resolved_entity: ResolvedEntity,
        entity: Entity,
    ) -> ResolutionRecord:
        return ResolutionRecord(
            resolution_method=method,
            resolution_reason=f"{method.value} matched {token!r}",
            resolution_confidence=ResolutionConfidence.HIGH,
            timestamp=datetime.now(timezone.utc).isoformat(),
            resolver_version=RESOLVER_VERSION,
            supporting_entities=[resolved_entity.source_entities[0], entity.id],
        )

    @staticmethod
    def _identifier_tokens(entity: Entity | ResolvedEntity) -> list[str]:
        primary = getattr(entity, "primary_identifier")
        return [primary]

    @staticmethod
    def _alias_tokens(entity: Entity | ResolvedEntity) -> list[str]:
        return [getattr(entity, "primary_identifier"), *getattr(entity, "aliases")]

    @staticmethod
    def _ip_tokens(entity: Entity | ResolvedEntity) -> list[str]:
        return [
            token
            for value in [
                getattr(entity, "primary_identifier"),
                *getattr(entity, "aliases"),
            ]
            if (token := IdentityResolver._ip_token(value)) is not None
        ]

    @staticmethod
    def _hostname_tokens(entity: Entity | ResolvedEntity) -> list[str]:
        if (
            getattr(entity, "type", getattr(entity, "entity_type", None))
            != EntityType.HOST
        ):
            return []
        return [
            value.lower()
            for value in [
                getattr(entity, "primary_identifier"),
                *getattr(entity, "aliases"),
            ]
            if IdentityResolver._ip_token(value) is None
        ]

    @staticmethod
    def _ip_token(value: str) -> str | None:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    @staticmethod
    def _aliases(primary_identifier: str, aliases: list[str]) -> list[str]:
        return IdentityResolver._unique_sorted(
            alias.strip()
            for alias in aliases
            if alias.strip() and alias.strip() != primary_identifier
        )

    @staticmethod
    def _unique_sorted(values) -> list[str]:
        return sorted(set(values))
