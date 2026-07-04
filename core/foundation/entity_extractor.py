"""
core.entity_extractor

Extracts Entity objects from a Finding.

MUST NOT:
  - correlate findings
  - merge/dedupe entities across findings
  - build graphs or relationships
  - consume raw evidence directly (only Finding objects)

ONLY responsibility: one Finding -> zero or more Entity objects.

Static class, matching FindingBuilder's shape.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from .entity import Entity, stable_entity_id
from .entity_schema import EntityValidationError, validate_entity
from .finding import EntityType, Finding

logger = logging.getLogger("thragg.entity_extractor")

# Evidence keys the extractor recognizes -> the EntityType they map to.
# Expanded to cover all EntityType values where evidence keys are known.
_EVIDENCE_ENTITY_MAP: dict[str, EntityType] = {
    "host": EntityType.HOST,
    "hostname": EntityType.HOST,
    "source_ip": EntityType.HOST,
    "ip": EntityType.HOST,
    "ip_address": EntityType.HOST,
    "user": EntityType.USER,
    "username": EntityType.USER,
    "service": EntityType.SERVICE,
    "service_name": EntityType.SERVICE,
    "application": EntityType.APPLICATION,
    "app": EntityType.APPLICATION,
    "port_entity": EntityType.PORT,
    "domain": EntityType.DOMAIN,
    "certificate": EntityType.CERTIFICATE,
    "process": EntityType.PROCESS,
    "file": EntityType.FILE,
    "registry_key": EntityType.REGISTRY_KEY,
    "container": EntityType.CONTAINER,
    "network": EntityType.NETWORK,
    "storage": EntityType.STORAGE,
    "database": EntityType.DATABASE,
    "cloud_resource": EntityType.CLOUD_RESOURCE,
    "subscription": EntityType.CLOUD_RESOURCE,
    "azure_object_id": EntityType.IDENTITY,
    "object_id": EntityType.IDENTITY,
    "upn": EntityType.IDENTITY,
    "identity": EntityType.IDENTITY,
}

# Evidence keys that describe an entity rather than identify one --
# attached as attributes on whichever entity is extracted, never
# turned into entities themselves.
_DESCRIPTIVE_EVIDENCE_KEYS = {"port", "protocol"}

_HOST_IDENTIFIER_PRIORITY = {
    "ip": 0,
    "source_ip": 1,
    "host": 2,
    "hostname": 3,
}


class EntityExtractor:
    """Static extractor. Do not instantiate -- call via classmethods."""

    @classmethod
    def extract(cls, finding: Finding) -> list[Entity]:
        """Extract all entities implied by a single Finding."""
        entities: list[Entity] = []
        entities_by_id: dict[str, Entity] = {}

        primary = cls._extract_primary(finding)
        if primary is not None:
            entities.append(primary)
            entities_by_id[primary.id] = primary

        for evidence_entity in cls._extract_from_evidence(finding):
            existing = entities_by_id.get(evidence_entity.id)
            if existing is None:
                entities.append(evidence_entity)
                entities_by_id[evidence_entity.id] = evidence_entity
            else:
                cls._merge_same_entity(existing, evidence_entity)

        return entities

    @classmethod
    def extract_batch(cls, findings: list[Finding]) -> list[Entity]:
        """Extract entities from a list of Findings. Order-independent ids."""
        entities: list[Entity] = []
        for finding in findings:
            entities.extend(cls.extract(finding))
        return entities

    # -- internals ----------------------------------------------------

    @classmethod
    def _extract_primary(cls, finding: Finding) -> Entity | None:
        """The finding's own entity_type + asset, if both are present."""
        if not finding.asset:
            return None
        return cls._build(
            entity_type=finding.entity_type,
            primary_identifier=finding.asset,
            finding=finding,
            attributes=cls._descriptive_attributes(finding),
        )

    @classmethod
    def _extract_from_evidence(cls, finding: Finding) -> list[Entity]:
        """Additional entities implied by recognized evidence keys, with aliases."""
        if not isinstance(finding.evidence, dict):
            return []

        # Group evidence values by EntityType to collect aliases
        grouped: dict[EntityType, list[tuple[str, str]]] = defaultdict(list)

        for key, value in finding.evidence.items():
            entity_type = _EVIDENCE_ENTITY_MAP.get(key)
            identifier = cls._coerce_identifier(value)
            if entity_type is None or identifier is None:
                continue
            grouped[entity_type].append((key, identifier))

        entities: list[Entity] = []
        descriptive_attrs = cls._descriptive_attributes(finding)

        for entity_type in EntityType:
            identifiers = grouped.get(entity_type)
            if not identifiers:
                continue
            primary_key, primary_value = cls._select_primary_identifier(
                entity_type, identifiers
            )
            aliases = cls._aliases_for(primary_value, identifiers)

            attributes = dict(descriptive_attrs)
            if entity_type == EntityType.HOST and primary_key in ("source_ip", "ip"):
                attributes["role"] = primary_key

            entity = cls._build(
                entity_type=entity_type,
                primary_identifier=primary_value,
                finding=finding,
                attributes=attributes,
                aliases=aliases,
            )
            if entity is not None:
                entities.append(entity)

        return entities

    @staticmethod
    def _select_primary_identifier(
        entity_type: EntityType, identifiers: list[tuple[str, str]]
    ) -> tuple[str, str]:
        """Select the primary identifier from a list of (key, value) pairs."""
        if entity_type == EntityType.HOST:
            return min(
                identifiers,
                key=lambda item: (_HOST_IDENTIFIER_PRIORITY.get(item[0], 99), item[1]),
            )
        return sorted(identifiers, key=lambda item: (item[0], item[1]))[0]

    @staticmethod
    def _aliases_for(
        primary_identifier: str, identifiers: list[tuple[str, str]]
    ) -> list[str]:
        aliases = [
            value for _, value in sorted(identifiers, key=lambda item: (item[0], item[1]))
        ]
        return EntityExtractor._normalize_aliases(primary_identifier, aliases)

    @classmethod
    def _merge_same_entity(cls, existing: Entity, incoming: Entity) -> None:
        existing.aliases = cls._normalize_aliases(
            existing.primary_identifier,
            [*existing.aliases, incoming.primary_identifier, *incoming.aliases],
        )
        existing.attributes.update(incoming.attributes)

    @staticmethod
    def _coerce_identifier(value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, (dict, list, tuple, set)):
            return None
        identifier = str(value).strip()
        return identifier or None

    @staticmethod
    def _normalize_aliases(primary_identifier: str, aliases: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for alias in aliases:
            alias = alias.strip()
            if not alias or alias == primary_identifier or alias in seen:
                continue
            normalized.append(alias)
            seen.add(alias)
        return normalized

    @staticmethod
    def _descriptive_attributes(finding: Finding) -> dict[str, Any]:
        if not isinstance(finding.evidence, dict):
            return {}
        return {
            k: v for k, v in finding.evidence.items() if k in _DESCRIPTIVE_EVIDENCE_KEYS
        }

    @classmethod
    def _build(
        cls,
        *,
        entity_type: EntityType,
        primary_identifier: str,
        finding: Finding,
        attributes: dict[str, Any],
        aliases: list[str] | None = None,
    ) -> Entity | None:
        try:
            entity = Entity(
                id=stable_entity_id(entity_type, primary_identifier),
                type=entity_type,
                primary_identifier=primary_identifier,
                source_module=finding.source_module,
                source_finding=finding.id,
                confidence=finding.confidence,
                aliases=cls._normalize_aliases(primary_identifier, aliases or []),
                attributes=attributes,
            )
            validate_entity(entity)
            return entity
        except EntityValidationError as exc:
            logger.warning(
                "Skipped malformed entity from finding %s: %s", finding.id, exc
            )
            return None
