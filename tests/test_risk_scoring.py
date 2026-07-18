from dataclasses import FrozenInstanceError

import pytest

from thragg.core.attack_chain.attack_chain import AttackChain
from thragg.core.attack_chain.chain_edge import ChainEdge
from thragg.core.foundation.finding import Confidence, Severity
from thragg.core.risk.risk_assessment import RiskAssessment
from thragg.core.risk.risk_contribution import RiskContribution
from thragg.core.risk.risk_level import RiskLevel
from thragg.core.risk.risk_schema import (
    RiskSchemaError,
    is_valid_risk_assessment,
    is_valid_risk_contribution,
    is_valid_scoring_policy,
    validate_risk_contribution,
)
from thragg.core.risk.score_factor import (
    ChainLengthFactor,
    ConfidenceFactor,
    CriticalAssetFactor,
    ExposureFactor,
    MITREFactor,
    ScoreFactor,
    SeverityFactor,
)
from thragg.core.risk.scoring_policy import ScoringPolicy


def _chain(**overrides) -> AttackChain:
    defaults = dict(
        id="chain-1",
        title="Initial access to database",
        description="A test attack chain.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        entry_point="corr-a",
        target="prod-db-1",
        timeline=(
            {
                "stage": "INITIAL_ACCESS",
                "timestamp": "2026-07-03T00:00:00Z",
                "correlation_id": "corr-a",
            },
            {
                "stage": "CREDENTIAL_ACCESS",
                "timestamp": "2026-07-03T00:01:00Z",
                "correlation_id": "corr-b",
            },
            {
                "stage": "IMPACT",
                "timestamp": "2026-07-03T00:02:00Z",
                "correlation_id": "corr-c",
            },
        ),
        correlations=("corr-a", "corr-b", "corr-c"),
        chain_edges=(
            ChainEdge("corr-a", "corr-b", "host-1", "HOST", 2, "Shared HOST entity"),
        ),
        entities=("host-1", "prod-db-1"),
        relationships=("rel-a",),
        supporting_findings=("finding-a",),
        recommendations=("Review exposed services.",),
        created_at="2026-07-03T00:00:00Z",
    )
    defaults.update(overrides)
    return AttackChain(**defaults)


def test_risk_contribution_is_immutable_and_validated():
    contribution = RiskContribution(
        id="contribution-1",
        factor_name="severity",
        score=30,
        max_contribution=40,
        reason="HIGH chain severity",
        source="attack_chain.severity",
    )

    assert is_valid_risk_contribution(contribution) is True
    assert contribution.to_dict()["score"] == 30
    with pytest.raises(FrozenInstanceError):
        contribution.score = 1


def test_risk_contribution_rejects_score_above_factor_cap():
    contribution = RiskContribution(
        id="contribution-1",
        factor_name="severity",
        score=41,
        max_contribution=40,
        reason="bad cap",
        source="test",
    )

    with pytest.raises(RiskSchemaError):
        validate_risk_contribution(contribution)


def test_score_factor_protocol_accepts_initial_factors():
    factors = (
        SeverityFactor(),
        ConfidenceFactor(),
        ExposureFactor(),
        CriticalAssetFactor(),
        MITREFactor(),
        ChainLengthFactor(),
    )

    assert all(isinstance(factor, ScoreFactor) for factor in factors)


def test_individual_factors_are_capped_and_deterministic():
    chain = _chain(severity=Severity.CRITICAL, confidence=Confidence.HIGH)
    factors = (
        SeverityFactor(),
        ConfidenceFactor(),
        ExposureFactor(),
        CriticalAssetFactor(),
        MITREFactor(),
        ChainLengthFactor(),
    )

    first = tuple(factor.evaluate(chain)[0] for factor in factors)
    second = tuple(factor.evaluate(chain)[0] for factor in factors)

    assert [item.factor_name for item in first] == [
        "severity",
        "confidence",
        "exposure",
        "critical_asset",
        "mitre",
        "chain_length",
    ]
    assert [item.score for item in first] == [40, 15, 15, 15, 6, 2]
    assert first == second
    assert all(item.score <= item.max_contribution for item in first)


def test_factor_scores_drop_when_chain_context_is_lower_risk():
    chain = _chain(
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        target="host-1",
        timeline=(
            {
                "stage": "DISCOVERY",
                "timestamp": "2026-07-03T00:00:00Z",
                "correlation_id": "corr-a",
            },
        ),
        correlations=("corr-a",),
        entities=("host-1",),
    )

    assert SeverityFactor().evaluate(chain)[0].score == 5
    assert ConfidenceFactor().evaluate(chain)[0].score == 5
    assert ExposureFactor().evaluate(chain)[0].score == 0
    assert CriticalAssetFactor().evaluate(chain)[0].score == 0
    assert MITREFactor().evaluate(chain)[0].score == 2
    assert ChainLengthFactor().evaluate(chain)[0].score == 0


def test_scoring_policy_contains_only_factor_tuple():
    policy = ScoringPolicy(
        (
            SeverityFactor(),
            ConfidenceFactor(),
            ExposureFactor(),
        )
    )

    assert is_valid_scoring_policy(policy) is True
    assert tuple(policy.__dataclass_fields__) == ("factors",)
    assert [factor.name for factor in policy.factors] == [
        "severity",
        "confidence",
        "exposure",
    ]


def test_risk_assessment_is_immutable_specific_and_serializable():
    contributions = (
        SeverityFactor().evaluate(_chain())[0],
        ConfidenceFactor().evaluate(_chain())[0],
    )
    assessment = RiskAssessment(
        id="risk-1",
        attack_chain_id="chain-1",
        score=sum(item.score for item in contributions),
        risk_level=RiskLevel.HIGH,
        contributions=contributions,
        summary="High risk chain.",
        recommendation="Review and remediate the chain.",
        created_at="2026-07-03T00:00:00Z",
        policy_version="m7-foundation",
    )

    assert is_valid_risk_assessment(assessment) is True
    assert tuple(assessment.__dataclass_fields__) == (
        "id",
        "attack_chain_id",
        "score",
        "risk_level",
        "contributions",
        "summary",
        "recommendation",
        "created_at",
        "policy_version",
        "label",
        "priority_rank",
    )
    assert assessment.to_dict()["contributions"][0]["factor_name"] == "severity"
    assert assessment.to_dict()["risk_level"] == "HIGH"
    with pytest.raises(FrozenInstanceError):
        assessment.score = 1
