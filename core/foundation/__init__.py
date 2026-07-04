"""Foundation package public API."""

from .core_relationship_fact import (
    RelationshipFact,
    RelationshipType,
    stable_relationship_fact_id,
)
from .core_relationship_schema import (
    RelationshipSchemaError,
    is_valid_relationship_fact,
    validate_relationship_fact,
)
from .core_relationship_validator import (
    InvalidRelationshipCombination,
    RelationshipValidator,
)
from .entity import Entity, stable_entity_id
from .entity_extractor import EntityExtractor
from .entity_registry import EntityRegistry, EntityRepository
from .entity_schema import EntityValidationError, is_valid_entity, validate_entity
from .finding import Confidence, EntityType, Finding, Severity
from .finding_builder import build_finding, build_findings_from_rule_results
from .finding_schema import FindingValidationError, is_valid_finding, validate_finding
from .identity_resolver import IdentityResolver
from .knowledge_base import KnowledgeBase
from .relationship_graph import RelationshipGraph
from .relationship_inference import (
    RelationshipInferenceRule,
    RelationshipInferencer,
    example_relationship_rules,
    relationship_inference_rule_from_dict,
)
from .relationship_repository import RelationshipRepository
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
    "Confidence",
    "Entity",
    "EntityExtractor",
    "EntityRegistry",
    "EntityRepository",
    "EntityType",
    "EntityValidationError",
    "Finding",
    "FindingValidationError",
    "IdentityResolver",
    "InvalidRelationshipCombination",
    "KnowledgeBase",
    "RelationshipFact",
    "RelationshipGraph",
    "RelationshipInferenceRule",
    "RelationshipInferencer",
    "RelationshipRepository",
    "RelationshipSchemaError",
    "RelationshipType",
    "RelationshipValidator",
    "ResolutionConfidence",
    "ResolutionMethod",
    "ResolutionRecord",
    "ResolutionValidationError",
    "ResolvedEntity",
    "Severity",
    "build_finding",
    "build_findings_from_rule_results",
    "example_relationship_rules",
    "is_valid_entity",
    "is_valid_finding",
    "is_valid_relationship_fact",
    "is_valid_resolution_record",
    "is_valid_resolved_entity",
    "relationship_inference_rule_from_dict",
    "stable_entity_id",
    "stable_relationship_fact_id",
    "stable_resolved_entity_id",
    "validate_entity",
    "validate_finding",
    "validate_relationship_fact",
    "validate_resolution_record",
    "validate_resolved_entity",
]
