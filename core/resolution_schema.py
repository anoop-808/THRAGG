"""
core.resolution_schema

Validation for identity resolution objects.
"""

from __future__ import annotations

from .finding import EntityType
from .resolved_entity import (
    ResolutionConfidence,
    ResolutionMethod,
    ResolutionRecord,
    ResolvedEntity,
)


class ResolutionValidationError(ValueError):
    """Raised when a resolution object fails schema validation."""


def validate_resolution_record(record: ResolutionRecord) -> None:
    """Validate a ResolutionRecord instance."""
    if not isinstance(record, ResolutionRecord):
        raise ResolutionValidationError(
            "ResolutionRecord must be a ResolutionRecord instance"
        )
    if not isinstance(record.resolution_method, ResolutionMethod):
        raise ResolutionValidationError(
            "ResolutionRecord.resolution_method must be a ResolutionMethod enum"
        )
    if not isinstance(record.resolution_confidence, ResolutionConfidence):
        raise ResolutionValidationError(
            "ResolutionRecord.resolution_confidence must be a ResolutionConfidence enum"
        )
    for field_name in ("resolution_reason", "timestamp", "resolver_version"):
        value = getattr(record, field_name)
        if not isinstance(value, str) or not value.strip():
            raise ResolutionValidationError(
                f"ResolutionRecord.{field_name} must be a non-empty string"
            )
    _validate_string_list(
        record.supporting_entities, "ResolutionRecord.supporting_entities"
    )


def validate_resolved_entity(resolved_entity: ResolvedEntity) -> None:
    """Validate a ResolvedEntity instance."""
    for field_name in ("id", "primary_identifier"):
        value = getattr(resolved_entity, field_name)
        if not isinstance(value, str) or not value.strip():
            raise ResolutionValidationError(
                f"ResolvedEntity.{field_name} must be a non-empty string"
            )
    if not isinstance(resolved_entity.entity_type, EntityType):
        raise ResolutionValidationError(
            "ResolvedEntity.entity_type must be an EntityType enum"
        )
    _validate_string_list(resolved_entity.aliases, "ResolvedEntity.aliases")
    _validate_string_list(
        resolved_entity.source_entities, "ResolvedEntity.source_entities"
    )
    _validate_string_list(
        resolved_entity.source_findings, "ResolvedEntity.source_findings"
    )
    _validate_string_list(
        resolved_entity.source_modules, "ResolvedEntity.source_modules"
    )
    _reject_duplicates(resolved_entity.aliases, "ResolvedEntity.aliases")
    _reject_duplicates(
        resolved_entity.source_entities, "ResolvedEntity.source_entities"
    )
    _reject_duplicates(
        resolved_entity.source_findings, "ResolvedEntity.source_findings"
    )
    _reject_duplicates(resolved_entity.source_modules, "ResolvedEntity.source_modules")
    if resolved_entity.primary_identifier in resolved_entity.aliases:
        raise ResolutionValidationError(
            "ResolvedEntity.aliases must not contain the primary_identifier"
        )
    if not isinstance(resolved_entity.attributes, dict):
        raise ResolutionValidationError("ResolvedEntity.attributes must be a dict")
    if not all(isinstance(key, str) for key in resolved_entity.attributes):
        raise ResolutionValidationError(
            "ResolvedEntity.attributes keys must be strings"
        )
    for record in resolved_entity.resolution_records:
        if not isinstance(record, ResolutionRecord):
            raise ResolutionValidationError(
                "ResolvedEntity.resolution_records must contain ResolutionRecord "
                "instances"
            )
        validate_resolution_record(record)


def is_valid_resolved_entity(resolved_entity: ResolvedEntity) -> bool:
    """Return True when a ResolvedEntity passes validation."""
    try:
        validate_resolved_entity(resolved_entity)
        return True
    except ResolutionValidationError:
        return False


def is_valid_resolution_record(record: ResolutionRecord) -> bool:
    """Return True when a ResolutionRecord passes validation."""
    try:
        validate_resolution_record(record)
        return True
    except ResolutionValidationError:
        return False


def _validate_string_list(values: list[str], field_name: str) -> None:
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ResolutionValidationError(f"{field_name} must be a list[str]")
    if any(not value.strip() for value in values):
        raise ResolutionValidationError(f"{field_name} must not contain blank strings")


def _reject_duplicates(values: list[str], field_name: str) -> None:
    if len(values) != len(set(values)):
        raise ResolutionValidationError(f"{field_name} must not contain duplicates")
