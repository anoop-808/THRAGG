"""
THRAGG core framework exports.
"""

from .entity import Entity, EntityType, stable_entity_id
from .entity_extractor import EntityExtractor
from .entity_schema import EntityValidationError, is_valid_entity, validate_entity
from .finding import (
    Confidence,
    EntityType as FindingEntityType,
    Finding,
    Severity,
)
from .finding_builder import build_finding, build_findings_from_rule_results
from .finding_schema import FindingValidationError, is_valid_finding, validate_finding
from .identity_resolver import IdentityResolver
from .resolution_schema import (
    ResolutionValidationError,
    is_valid_resolution_record,
    is_valid_resolved_entity,
    validate_resolution_record,
    validate_resolved_entity,
)
from .resolved_entity import (
    ResolutionConfidence,
    ResolutionMethod,
    ResolutionRecord,
    ResolvedEntity,
    stable_resolved_entity_id,
)

__all__ = [
    # Finding subsystem
    "Finding",
    "Severity",
    "Confidence",
    "FindingEntityType",
    "build_finding",
    "build_findings_from_rule_results",
    "validate_finding",
    "is_valid_finding",
    "FindingValidationError",
    # Entity subsystem
    "Entity",
    "EntityType",
    "stable_entity_id",
    "EntityExtractor",
    "validate_entity",
    "is_valid_entity",
    "EntityValidationError",
    # Identity resolution subsystem
    "ResolvedEntity",
    "ResolutionRecord",
    "ResolutionMethod",
    "ResolutionConfidence",
    "stable_resolved_entity_id",
    "IdentityResolver",
    "validate_resolved_entity",
    "is_valid_resolved_entity",
    "validate_resolution_record",
    "is_valid_resolution_record",
    "ResolutionValidationError",
]
