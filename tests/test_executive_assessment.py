from dataclasses import FrozenInstanceError

import pytest

from thragg.core.attack_chain.attack_chain import AttackChain
from thragg.core.attack_chain.chain_edge import ChainEdge
from thragg.core.correlation.correlation import Correlation
from thragg.core.executive.executive_assessment import (
    ExecutiveAssessment,
    stable_executive_assessment_id,
)
from thragg.core.executive.executive_schema import (
    ExecutiveSchemaError,
    is_valid_count_metric,
    is_valid_executive_assessment,
    is_valid_framework_snapshot,
    is_valid_framework_statistics,
    is_valid_observation,
    is_valid_traceability_map,
    validate_executive_assessment,
    validate_framework_snapshot,
    validate_framework_statistics,
    validate_observation,
    validate_traceability_map,
)
from thragg.core.foundation.finding import Confidence, Severity
from thragg.core.executive.framework_snapshot import FrameworkSnapshot
from thragg.core.executive.framework_statistics import CountMetric, FrameworkStatistics
from thragg.core.executive.observation import Observation, ObservationCategory
from thragg.core.risk.risk_assessment import RiskAssessment
from thragg.core.risk.risk_contribution import RiskContribution
from thragg.core.risk.risk_level import RiskLevel
from thragg.core.executive.security_posture import SecurityPosture
from thragg.core.shared.traceability_map import TraceabilityMap


def _correlation(**overrides) -> Correlation:
    defaults = dict(
        id="corr-1",
        rule_id="rule-1",
        title="Public SSH",
        description="A public SSH path exists.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        recommendation="Restrict SSH.",
        mitre=("T1021.004",),
        category="Initial Access",
        tags=("ssh",),
        timestamp="2026-07-03T00:00:00Z",
        matched_entities=({"id": "host-1", "entity_type": "HOST"},),
        matched_relationships=("rel-1",),
        supporting_findings=("finding-1",),
        correlation_explanation={"stage": "INITIAL_ACCESS"},
    )
    defaults.update(overrides)
    return Correlation(**defaults)


def _chain(**overrides) -> AttackChain:
    defaults = dict(
        id="chain-1",
        title="Initial access chain",
        description="A deterministic test chain.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        entry_point="corr-1",
        target="corr-1",
        timeline=(
            {
                "stage": "INITIAL_ACCESS",
                "timestamp": "2026-07-03T00:00:00Z",
                "correlation_id": "corr-1",
            },
        ),
        correlations=("corr-1",),
        chain_edges=(
            ChainEdge("corr-1", "corr-2", "host-1", "HOST", 2, "Shared HOST entity"),
        ),
        entities=("host-1",),
        relationships=("rel-1",),
        supporting_findings=("finding-1",),
        recommendations=("Restrict SSH.",),
        created_at="2026-07-03T00:00:00Z",
    )
    defaults.update(overrides)
    return AttackChain(**defaults)


def _risk(**overrides) -> RiskAssessment:
    contribution = RiskContribution(
        id="contribution-1",
        factor_name="severity",
        score=30,
        max_contribution=40,
        reason="HIGH chain severity",
        source="attack_chain.severity",
    )
    defaults = dict(
        id="risk-1",
        attack_chain_id="chain-1",
        score=30,
        risk_level=RiskLevel.HIGH,
        contributions=(contribution,),
        summary="High risk chain.",
        recommendation="Review the chain.",
        created_at="2026-07-03T00:00:00Z",
        policy_version="m7-foundation",
    )
    defaults.update(overrides)
    return RiskAssessment(**defaults)


def _statistics(**overrides) -> FrameworkStatistics:
    defaults = dict(
        total_findings=3,
        total_entities=2,
        total_relationships=1,
        total_correlations=1,
        total_attack_chains=1,
        risk_counts=(CountMetric("HIGH", 1),),
        top_entity_types=(CountMetric("HOST", 2),),
        top_attack_stages=(CountMetric("INITIAL_ACCESS", 1),),
        top_attack_categories=(CountMetric("Initial Access", 1),),
    )
    defaults.update(overrides)
    return FrameworkStatistics(**defaults)


def _observation(**overrides) -> Observation:
    defaults = dict(
        id="obs-1",
        category=ObservationCategory.EXPOSURE,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        text="Public access creates a credible initial access path.",
        supporting_object_ids=("risk-1", "chain-1", "corr-1"),
    )
    defaults.update(overrides)
    return Observation(**defaults)


def _traceability(**overrides) -> TraceabilityMap:
    defaults = dict(
        observation_to_risks=(("obs-1", ("risk-1",)),),
        observation_to_attack_chains=(("obs-1", ("chain-1",)),),
        observation_to_correlations=(("obs-1", ("corr-1",)),),
        recommendation_to_observations=(("Restrict SSH.", ("obs-1",)),),
    )
    defaults.update(overrides)
    return TraceabilityMap(**defaults)


def _assessment(**overrides) -> ExecutiveAssessment:
    defaults = dict(
        id=stable_executive_assessment_id(
            "m8-snapshot-v1",
            "2026-07-03T00:00:00Z",
            "m8-foundation",
        ),
        summary="Environment has one high-risk initial access path.",
        observations=(_observation(),),
        recommendations=("Restrict SSH.",),
        statistics=_statistics(),
        security_posture=SecurityPosture.HIGH_RISK,
        traceability=_traceability(),
        engine_version="m8-foundation",
        generated_at="2026-07-03T00:00:00Z",
    )
    defaults.update(overrides)
    return ExecutiveAssessment(**defaults)


def test_framework_snapshot_is_frozen_counts_only_and_validated():
    snapshot = FrameworkSnapshot(
        risk_assessments=(_risk(),),
        attack_chains=(_chain(),),
        correlations=(_correlation(),),
        finding_count=3,
        entity_count=2,
        resolved_entity_count=1,
        relationship_count=1,
        snapshot_version="m8-snapshot-v1",
        generated_at="2026-07-03T00:00:00Z",
    )

    assert is_valid_framework_snapshot(snapshot) is True
    assert tuple(snapshot.__dataclass_fields__) == (
        "risk_assessments",
        "attack_chains",
        "correlations",
        "finding_count",
        "entity_count",
        "resolved_entity_count",
        "relationship_count",
        "snapshot_version",
        "generated_at",
    )
    assert "findings" not in snapshot.__dataclass_fields__
    assert snapshot.to_dict()["resolved_entity_count"] == 1
    assert snapshot.to_dict()["snapshot_version"] == "m8-snapshot-v1"
    with pytest.raises(FrozenInstanceError):
        snapshot.finding_count = 4


def test_framework_snapshot_rejects_negative_counts():
    snapshot = FrameworkSnapshot(
        risk_assessments=(),
        attack_chains=(),
        correlations=(),
        finding_count=-1,
        entity_count=0,
        resolved_entity_count=0,
        relationship_count=0,
        snapshot_version="m8-snapshot-v1",
        generated_at="2026-07-03T00:00:00Z",
    )

    with pytest.raises(ExecutiveSchemaError):
        validate_framework_snapshot(snapshot)


def test_framework_statistics_are_typed_frozen_and_serializable():
    statistics = _statistics()

    assert is_valid_count_metric(statistics.top_entity_types[0]) is True
    assert is_valid_framework_statistics(statistics) is True
    assert tuple(statistics.__dataclass_fields__) == (
        "total_findings",
        "total_entities",
        "total_relationships",
        "total_correlations",
        "total_attack_chains",
        "risk_counts",
        "top_entity_types",
        "top_attack_stages",
        "top_attack_categories",
    )
    assert statistics.to_dict()["risk_counts"] == [{"name": "HIGH", "count": 1}]
    assert statistics.to_dict()["top_entity_types"] == [
        {"name": "HOST", "count": 2}
    ]
    assert statistics.risk_high_count == 1
    assert statistics.risk_critical_count == 0
    with pytest.raises(FrozenInstanceError):
        statistics.total_findings = 4


def test_framework_statistics_reject_invalid_counts():
    statistics = _statistics(risk_counts=(CountMetric("HIGH", -1),))

    with pytest.raises(ExecutiveSchemaError):
        validate_framework_statistics(statistics)


def test_observation_is_frozen_traceable_and_deterministically_serialized():
    observation = _observation(supporting_object_ids=["risk-1", "chain-1"])

    assert is_valid_observation(observation) is True
    assert observation.supporting_object_ids == ("risk-1", "chain-1")
    assert observation.to_dict() == {
        "id": "obs-1",
        "category": "EXPOSURE",
        "severity": "HIGH",
        "confidence": "HIGH",
        "text": "Public access creates a credible initial access path.",
        "supporting_object_ids": ["risk-1", "chain-1"],
    }
    with pytest.raises(FrozenInstanceError):
        observation.text = "changed"


def test_observation_rejects_plain_string_enums():
    observation = _observation(category="EXPOSURE")

    with pytest.raises(ExecutiveSchemaError):
        validate_observation(observation)


def test_traceability_map_is_tuple_only_and_validated():
    traceability = TraceabilityMap(
        observation_to_risks=[("obs-1", ["risk-1"])],
        observation_to_attack_chains=[("obs-1", ["chain-1"])],
        observation_to_correlations=[("obs-1", ["corr-1"])],
        recommendation_to_observations=[("Restrict SSH.", ["obs-1"])],
    )

    assert is_valid_traceability_map(traceability) is True
    assert traceability.observation_to_risks == (("obs-1", ("risk-1",)),)
    assert traceability.observation_to_correlations == (("obs-1", ("corr-1",)),)
    with pytest.raises(FrozenInstanceError):
        traceability.observation_to_risks = ()


def test_traceability_map_rejects_blank_ids():
    traceability = _traceability(observation_to_risks=(("obs-1", ("",)),))

    with pytest.raises(ExecutiveSchemaError):
        validate_traceability_map(traceability)


def test_security_posture_enum_contains_only_m8_contract_values():
    assert [item.value for item in SecurityPosture] == [
        "HEALTHY",
        "OBSERVE",
        "ELEVATED",
        "HIGH_RISK",
        "CRITICAL",
    ]


def test_executive_assessment_is_contract_only_frozen_and_validated():
    assessment = _assessment()

    assert is_valid_executive_assessment(assessment) is True
    assert tuple(assessment.__dataclass_fields__) == (
        "id",
        "summary",
        "observations",
        "recommendations",
        "statistics",
        "security_posture",
        "traceability",
        "engine_version",
        "generated_at",
    )
    assert not hasattr(assessment, "render")
    assert not hasattr(assessment, "generate_report")
    assert assessment.to_dict()["id"] == "exec-5677533e220e6a47"
    assert tuple(assessment.to_dict())[0] == "id"
    assert assessment.to_dict()["security_posture"] == "HIGH_RISK"
    assert assessment.to_dict()["traceability"]["observation_to_correlations"] == [
        ("obs-1", ["corr-1"])
    ]
    with pytest.raises(FrozenInstanceError):
        assessment.summary = "changed"


def test_stable_executive_assessment_id_is_deterministic():
    first = stable_executive_assessment_id(
        "m8-snapshot-v1",
        "2026-07-03T00:00:00Z",
        "m8-foundation",
    )
    second = stable_executive_assessment_id(
        "m8-snapshot-v1",
        "2026-07-03T00:00:00Z",
        "m8-foundation",
    )
    changed = stable_executive_assessment_id(
        "m8-snapshot-v2",
        "2026-07-03T00:00:00Z",
        "m8-foundation",
    )

    assert first == second
    assert first == "exec-5677533e220e6a47"
    assert first != changed


def test_executive_assessment_rejects_blank_id():
    assessment = _assessment(id=" ")

    with pytest.raises(ExecutiveSchemaError):
        validate_executive_assessment(assessment)


def test_executive_assessment_rejects_invalid_nested_contracts():
    assessment = _assessment(observations=("obs-1",))

    with pytest.raises(ExecutiveSchemaError):
        validate_executive_assessment(assessment)
