"""
core.entity_schema

Validation for Entity objects. Mirrors finding_schema.py.
Entity dataclass carries no validation logic itself.
"""

from __future__ import annotations

from .entity import Entity
from .finding import Confidence, EntityType

REQUIRED_STRING_FIELDS = (
    "id",
    "primary_identifier",
    "source_module",
    "source_finding",
)


class EntityValidationError(ValueError):
    """Raised when an Entity fails schema validation."""


def validate_entity(entity: Entity) -> None:
    """
    Validate an Entity instance.

    Raises EntityValidationError on the first violation found.
    """
    for field_name in REQUIRED_STRING_FIELDS:
        value = getattr(entity, field_name)
        if not isinstance(value, str) or not value.strip():
            raise EntityValidationError(
                f"Entity.{field_name} must be a non-empty string, got {value!r}"
            )

    if not isinstance(entity.type, EntityType):
        raise EntityValidationError(
            f"Entity.type must be an EntityType enum, got {entity.type!r}"
        )

    if not isinstance(entity.confidence, Confidence):
        raise EntityValidationError(
            f"Entity.confidence must be a Confidence enum, got {entity.confidence!r}"
        )

    if not isinstance(entity.aliases, list) or not all(
        isinstance(a, str) for a in entity.aliases
    ):
        raise EntityValidationError("Entity.aliases must be a list[str]")

    seen_aliases: set[str] = set()
    for alias in entity.aliases:
        if not alias.strip():
            raise EntityValidationError("Entity.aliases must not contain blank strings")
        if alias == entity.primary_identifier:
            raise EntityValidationError(
                "Entity.aliases must not contain the primary_identifier"
            )
        if alias in seen_aliases:
            raise EntityValidationError("Entity.aliases must not contain duplicates")
        seen_aliases.add(alias)

    if not isinstance(entity.attributes, dict):
        raise EntityValidationError("Entity.attributes must be a dict")

    if not all(isinstance(k, str) for k in entity.attributes):
        raise EntityValidationError("Entity.attributes keys must be strings")


def is_valid_entity(entity: Entity) -> bool:
    """Non-raising convenience wrapper used by callers that want to skip-and-log."""
    try:
        validate_entity(entity)
        return True
    except EntityValidationError:
        return False
