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
from .knowledge_base import KnowledgeBase
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
from .relationship_graph import RelationshipGraph
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
from .correlation import Correlation
from .correlation_builder import CorrelationBuilder, stable_correlation_id
from .correlation_engine import CorrelationEngine
from .correlation_repository import CorrelationRepository
from .correlation_rule import (
    AttackStage,
    CorrelationRule,
    EntityAttributeEqualsCondition,
    RelationshipEvidenceEqualsCondition,
    RelationshipPattern,
    RuleRegistry,
)
from .correlation_schema import (
    CorrelationSchemaError,
    is_valid_correlation,
    validate_correlation,
)
from .pattern_evaluator import PatternEvaluator, PatternMatch
from .attack_chain import AttackChain
from .attack_chain_builder import AttackChainBuilder, stable_attack_chain_id
from .attack_chain_engine import AttackChainEngine
from .attack_chain_repository import AttackChainRepository
from .attack_chain_schema import (
    AttackChainSchemaError,
    is_valid_attack_chain,
    validate_attack_chain,
)
from .chain_candidate import ChainCandidate
from .chain_discovery_engine import ChainDiscoveryEngine
from .chain_edge import AFFINITY_WEIGHTS, ChainEdge, affinity_score
from .chain_validator import ChainValidator
from .priority_ranker import PriorityRanker
from .risk_assessment import RiskAssessment
from .risk_builder import RiskBuilder, stable_risk_assessment_id
from .risk_contribution import RiskContribution
from .risk_engine import RiskEngine
from .risk_level import RiskLevel
from .risk_repository import RiskRepository
from .risk_schema import (
    RiskSchemaError,
    is_valid_risk_assessment,
    is_valid_risk_contribution,
    is_valid_scoring_policy,
    validate_risk_assessment,
    validate_risk_contribution,
    validate_scoring_policy,
)
from .executive_assessment import (
    ExecutiveAssessment,
    stable_executive_assessment_id,
)
from .executive_schema import (
    ExecutiveSchemaError,
    is_valid_count_metric,
    is_valid_executive_assessment,
    is_valid_framework_snapshot,
    is_valid_framework_statistics,
    is_valid_observation,
    is_valid_traceability_map,
    validate_count_metric,
    validate_executive_assessment,
    validate_framework_snapshot,
    validate_framework_statistics,
    validate_observation,
    validate_traceability_map,
)
from .framework_snapshot import FrameworkSnapshot
from .framework_statistics import CountMetric, FrameworkStatistics
from .observation import Observation, ObservationCategory
from .security_posture import SecurityPosture
from .traceability_map import TraceabilityMap
from .score_factor import (
    ChainLengthFactor,
    ConfidenceFactor,
    CriticalAssetFactor,
    ExposureFactor,
    MITREFactor,
    ScoreFactor,
    SeverityFactor,
)
from .scoring_policy import ScoringPolicy

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
    # Relationship subsystem
    "RelationshipFact",
    "RelationshipType",
    "stable_relationship_fact_id",
    "validate_relationship_fact",
    "is_valid_relationship_fact",
    "RelationshipSchemaError",
    "RelationshipValidator",
    "InvalidRelationshipCombination",
    # Knowledge subsystem
    "KnowledgeBase",
    "RelationshipGraph",
    # Correlation subsystem
    "AttackStage",
    "Correlation",
    "CorrelationRule",
    "RelationshipPattern",
    "EntityAttributeEqualsCondition",
    "RelationshipEvidenceEqualsCondition",
    "RuleRegistry",
    "PatternEvaluator",
    "PatternMatch",
    "CorrelationBuilder",
    "stable_correlation_id",
    "CorrelationRepository",
    "CorrelationEngine",
    "validate_correlation",
    "is_valid_correlation",
    "CorrelationSchemaError",
    # Attack chain subsystem
    "AttackChain",
    "ChainEdge",
    "AFFINITY_WEIGHTS",
    "affinity_score",
    "ChainCandidate",
    "ChainDiscoveryEngine",
    "ChainValidator",
    "AttackChainBuilder",
    "stable_attack_chain_id",
    "AttackChainRepository",
    "AttackChainEngine",
    "validate_attack_chain",
    "is_valid_attack_chain",
    "AttackChainSchemaError",
    # Risk scoring subsystem
    "RiskContribution",
    "ScoreFactor",
    "SeverityFactor",
    "ConfidenceFactor",
    "ExposureFactor",
    "CriticalAssetFactor",
    "MITREFactor",
    "ChainLengthFactor",
    "ScoringPolicy",
    "RiskAssessment",
    "validate_risk_contribution",
    "is_valid_risk_contribution",
    "RiskBuilder",
    "RiskLevel",
    "stable_risk_assessment_id",
    "RiskRepository",
    "PriorityRanker",
    "RiskEngine",
    "validate_scoring_policy",
    "is_valid_scoring_policy",
    "validate_risk_assessment",
    "is_valid_risk_assessment",
    "RiskSchemaError",
    # Executive assessment subsystem
    "FrameworkSnapshot",
    "CountMetric",
    "FrameworkStatistics",
    "Observation",
    "ObservationCategory",
    "TraceabilityMap",
    "SecurityPosture",
    "ExecutiveAssessment",
    "stable_executive_assessment_id",
    "validate_framework_snapshot",
    "is_valid_framework_snapshot",
    "validate_count_metric",
    "is_valid_count_metric",
    "validate_framework_statistics",
    "is_valid_framework_statistics",
    "validate_observation",
    "is_valid_observation",
    "validate_traceability_map",
    "is_valid_traceability_map",
    "validate_executive_assessment",
    "is_valid_executive_assessment",
    "ExecutiveSchemaError",
]
