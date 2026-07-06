"""
core.executive_schema
=====================

Structural validation for Milestone 8 executive assessment contracts.
"""

from __future__ import annotations

from ..attack_chain.attack_chain import AttackChain
from ..correlation.correlation import Correlation
from .executive_assessment import ExecutiveAssessment
from .executive_validator import ExecutiveValidationError, ExecutiveValidator
from ..foundation.finding import Confidence, Severity
from .framework_snapshot import FrameworkSnapshot
from .framework_statistics import CountMetric, FrameworkStatistics
from .observation import Observation, ObservationCategory
from ..risk.risk_assessment import RiskAssessment
from .security_posture import SecurityPosture
from ..shared.traceability_map import TraceabilityMap

__all__ = [
    "ExecutiveSchemaError",
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
]


class ExecutiveSchemaError(ValueError):
    """Raised when an M8 contract fails structural validation."""


def validate_framework_snapshot(snapshot: FrameworkSnapshot) -> None:
    """Validate a FrameworkSnapshot without mutating it."""
    if not isinstance(snapshot.risk_assessments, tuple) or not all(
        isinstance(item, RiskAssessment) for item in snapshot.risk_assessments
    ):
        raise ExecutiveSchemaError(
            "FrameworkSnapshot.risk_assessments must be tuple[RiskAssessment]"
        )
    if not isinstance(snapshot.attack_chains, tuple) or not all(
        isinstance(item, AttackChain) for item in snapshot.attack_chains
    ):
        raise ExecutiveSchemaError(
            "FrameworkSnapshot.attack_chains must be tuple[AttackChain]"
        )
    if not isinstance(snapshot.correlations, tuple) or not all(
        isinstance(item, Correlation) for item in snapshot.correlations
    ):
        raise ExecutiveSchemaError(
            "FrameworkSnapshot.correlations must be tuple[Correlation]"
        )
    _non_negative_int(snapshot.finding_count, "FrameworkSnapshot.finding_count")
    _non_negative_int(snapshot.entity_count, "FrameworkSnapshot.entity_count")
    _non_negative_int(
        snapshot.resolved_entity_count,
        "FrameworkSnapshot.resolved_entity_count",
    )
    _non_negative_int(
        snapshot.relationship_count,
        "FrameworkSnapshot.relationship_count",
    )
    _non_empty_string(snapshot.snapshot_version, "FrameworkSnapshot.snapshot_version")
    _non_empty_string(snapshot.generated_at, "FrameworkSnapshot.generated_at")


def is_valid_framework_snapshot(snapshot: FrameworkSnapshot) -> bool:
    """Return True when a FrameworkSnapshot passes schema validation."""
    try:
        validate_framework_snapshot(snapshot)
        return True
    except ExecutiveSchemaError:
        return False


def validate_count_metric(metric: CountMetric) -> None:
    """Validate a CountMetric without mutating it."""
    _non_empty_string(metric.name, "CountMetric.name")
    _non_negative_int(metric.count, "CountMetric.count")


def is_valid_count_metric(metric: CountMetric) -> bool:
    """Return True when a CountMetric passes schema validation."""
    try:
        validate_count_metric(metric)
        return True
    except ExecutiveSchemaError:
        return False


def validate_framework_statistics(statistics: FrameworkStatistics) -> None:
    """Validate FrameworkStatistics without mutating it."""
    for field_name in (
        "total_findings",
        "total_entities",
        "total_relationships",
        "total_correlations",
        "total_attack_chains",
    ):
        _non_negative_int(
            getattr(statistics, field_name),
            f"FrameworkStatistics.{field_name}",
        )
    _count_metrics(statistics.risk_counts, "risk_counts")
    _count_metrics(statistics.top_entity_types, "top_entity_types")
    _count_metrics(statistics.top_attack_stages, "top_attack_stages")
    _count_metrics(statistics.top_attack_categories, "top_attack_categories")


def is_valid_framework_statistics(statistics: FrameworkStatistics) -> bool:
    """Return True when FrameworkStatistics passes schema validation."""
    try:
        validate_framework_statistics(statistics)
        return True
    except ExecutiveSchemaError:
        return False


def validate_observation(observation: Observation) -> None:
    """Validate an Observation without mutating it."""
    _non_empty_string(observation.id, "Observation.id")
    _non_empty_string(observation.text, "Observation.text")
    if not isinstance(observation.category, ObservationCategory):
        raise ExecutiveSchemaError(
            "Observation.category must be an ObservationCategory enum"
        )
    if not isinstance(observation.severity, Severity):
        raise ExecutiveSchemaError("Observation.severity must be a Severity enum")
    if not isinstance(observation.confidence, Confidence):
        raise ExecutiveSchemaError("Observation.confidence must be a Confidence enum")
    _strings(observation.supporting_object_ids, "Observation.supporting_object_ids")


def is_valid_observation(observation: Observation) -> bool:
    """Return True when an Observation passes schema validation."""
    try:
        validate_observation(observation)
        return True
    except ExecutiveSchemaError:
        return False


def validate_traceability_map(traceability: TraceabilityMap) -> None:
    """Validate a TraceabilityMap without mutating it."""
    _string_tuple_map(
        traceability.observation_to_risks,
        "TraceabilityMap.observation_to_risks",
    )
    _string_tuple_map(
        traceability.observation_to_attack_chains,
        "TraceabilityMap.observation_to_attack_chains",
    )
    _string_tuple_map(
        traceability.observation_to_correlations,
        "TraceabilityMap.observation_to_correlations",
    )
    _string_tuple_map(
        traceability.recommendation_to_observations,
        "TraceabilityMap.recommendation_to_observations",
    )


def is_valid_traceability_map(traceability: TraceabilityMap) -> bool:
    """Return True when a TraceabilityMap passes schema validation."""
    try:
        validate_traceability_map(traceability)
        return True
    except ExecutiveSchemaError:
        return False


def validate_executive_assessment(assessment: ExecutiveAssessment) -> None:
    """Validate an ExecutiveAssessment without mutating it."""
    try:
        ExecutiveValidator().validate(assessment)
    except ExecutiveValidationError as exc:
        raise ExecutiveSchemaError(str(exc)) from exc
    _non_empty_string(assessment.id, "ExecutiveAssessment.id")
    _non_empty_string(assessment.summary, "ExecutiveAssessment.summary")
    _non_empty_string(
        assessment.engine_version,
        "ExecutiveAssessment.engine_version",
    )
    _non_empty_string(assessment.generated_at, "ExecutiveAssessment.generated_at")
    if not isinstance(assessment.security_posture, SecurityPosture):
        raise ExecutiveSchemaError(
            "ExecutiveAssessment.security_posture must be a SecurityPosture enum"
        )
    if assessment.statistics is None:
        return
    if not isinstance(assessment.statistics, FrameworkStatistics):
        raise ExecutiveSchemaError(
            "ExecutiveAssessment.statistics must be FrameworkStatistics"
        )
    validate_framework_statistics(assessment.statistics)
    if assessment.traceability is None:
        return
    if not isinstance(assessment.traceability, TraceabilityMap):
        raise ExecutiveSchemaError(
            "ExecutiveAssessment.traceability must be TraceabilityMap"
        )
    validate_traceability_map(assessment.traceability)
    if not isinstance(assessment.observations, tuple) or not all(
        isinstance(item, Observation) for item in assessment.observations
    ):
        raise ExecutiveSchemaError(
            "ExecutiveAssessment.observations must be tuple[Observation]"
        )
    for observation in assessment.observations:
        validate_observation(observation)
    _strings(assessment.recommendations, "ExecutiveAssessment.recommendations")


def is_valid_executive_assessment(assessment: ExecutiveAssessment) -> bool:
    """Return True when an ExecutiveAssessment passes schema validation."""
    try:
        validate_executive_assessment(assessment)
        return True
    except ExecutiveSchemaError:
        return False


def _count_metrics(value: object, field_name: str) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, CountMetric) for item in value
    ):
        raise ExecutiveSchemaError(
            f"FrameworkStatistics.{field_name} must be tuple[CountMetric]"
        )
    for item in value:
        validate_count_metric(item)


def _string_tuple_map(value: object, field_name: str) -> None:
    if not isinstance(value, tuple):
        raise ExecutiveSchemaError(f"{field_name} must be a tuple")
    for item in value:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not item[0].strip()
        ):
            raise ExecutiveSchemaError(
                f"{field_name} entries must be tuple[str, tuple[str, ...]]"
            )
        _strings(item[1], field_name)


def _strings(value: object, field_name: str) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise ExecutiveSchemaError(
            f"{field_name} must be a tuple of non-empty strings"
        )


def _non_empty_string(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ExecutiveSchemaError(f"{field_name} must be a non-empty string")


def _non_negative_int(value: object, field_name: str) -> None:
    if not isinstance(value, int) or value < 0:
        raise ExecutiveSchemaError(f"{field_name} must be a non-negative int")
