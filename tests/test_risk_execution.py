from thragg.core.attack_chain import AttackChain
from thragg.core.chain_edge import ChainEdge
from thragg.core.finding import Confidence, Severity
from thragg.core.priority_ranker import PriorityRanker
from thragg.core.risk_assessment import RiskAssessment
from thragg.core.risk_builder import RiskBuilder
from thragg.core.risk_contribution import RiskContribution
from thragg.core.risk_engine import RiskEngine
from thragg.core.risk_level import RiskLevel
from thragg.core.risk_repository import RiskRepository
from thragg.core.score_factor import (
    ChainLengthFactor,
    ConfidenceFactor,
    CriticalAssetFactor,
    ExposureFactor,
    MITREFactor,
    SeverityFactor,
)
from thragg.core.scoring_policy import ScoringPolicy


def _chain(chain_id: str = "chain-1", **overrides) -> AttackChain:
    defaults = dict(
        id=chain_id,
        title=f"Attack chain {chain_id}",
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
                "stage": "IMPACT",
                "timestamp": "2026-07-03T00:01:00Z",
                "correlation_id": "corr-b",
            },
        ),
        correlations=("corr-a", "corr-b"),
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


def _assessment(
    assessment_id: str,
    score: int,
    attack_chain_id: str | None = None,
) -> RiskAssessment:
    return RiskAssessment(
        id=assessment_id,
        attack_chain_id=attack_chain_id or assessment_id.replace("risk", "chain"),
        score=score,
        risk_level=RiskLevel.HIGH,
        contributions=(),
        summary="Risk summary.",
        recommendation="Review it.",
        created_at="2026-07-03T00:00:00Z",
        policy_version="test",
    )


class FixedFactor:
    name = "fixed"

    def __init__(self, score: int) -> None:
        self.score = score

    def evaluate(self, chain: AttackChain) -> tuple[RiskContribution, ...]:
        return (
            RiskContribution(
                id=f"fixed-{chain.id}-{self.score}",
                factor_name=self.name,
                score=self.score,
                max_contribution=self.score,
                reason="Fixed test contribution",
                source="test",
            ),
        )


def test_risk_builder_collects_aggregates_and_classifies():
    policy = ScoringPolicy((FixedFactor(20), FixedFactor(50)))

    assessment = RiskBuilder(policy_version="test").build(
        _chain(),
        policy,
        created_at="2026-07-03T01:00:00Z",
    )

    assert assessment.attack_chain_id == "chain-1"
    assert assessment.score == 70
    assert assessment.risk_level == RiskLevel.HIGH
    assert assessment.created_at == "2026-07-03T01:00:00Z"
    assert [item.score for item in assessment.contributions] == [20, 50]
    assert assessment.priority_rank is None


def test_risk_builder_clamps_final_score_to_100():
    policy = ScoringPolicy((FixedFactor(80), FixedFactor(40)))

    assessment = RiskBuilder(policy_version="test").build(_chain(), policy)

    assert assessment.score == 100
    assert assessment.risk_level == RiskLevel.CRITICAL


def test_risk_builder_uses_info_for_scores_below_25():
    policy = ScoringPolicy((FixedFactor(24),))

    assessment = RiskBuilder(policy_version="test").build(_chain(), policy)

    assert assessment.risk_level == RiskLevel.INFO


def test_risk_builder_regression_uses_existing_factors_without_ranking_or_storage():
    policy = ScoringPolicy(
        (
            SeverityFactor(),
            ConfidenceFactor(),
            ExposureFactor(),
            CriticalAssetFactor(),
            MITREFactor(),
            ChainLengthFactor(),
        )
    )

    assessment = RiskBuilder(policy_version="test").build(_chain(), policy)

    assert [item.factor_name for item in assessment.contributions] == [
        "severity",
        "confidence",
        "exposure",
        "critical_asset",
        "mitre",
        "chain_length",
    ]
    assert assessment.score == 75
    assert assessment.priority_rank is None


def test_priority_ranker_ranks_by_score_descending_with_deterministic_ties():
    ranked = PriorityRanker().rank(
        (
            _assessment("risk-c", 20),
            _assessment("risk-b", 90),
            _assessment("risk-a", 90),
        )
    )

    assert [(item.id, item.priority_rank) for item in ranked] == [
        ("risk-a", 1),
        ("risk-b", 2),
        ("risk-c", 3),
    ]


def test_risk_repository_stores_prevents_duplicates_and_orders_by_id():
    repository = RiskRepository()
    assert repository.add(_assessment("risk-b", 20)) is True
    assert repository.add(_assessment("risk-a", 90)) is True

    assert [item.id for item in repository.all()] == ["risk-a", "risk-b"]
    assert repository.add(_assessment("risk-a", 30)) is False


def test_risk_engine_orchestrates_builder_repository_and_ranker():
    policy = ScoringPolicy((FixedFactor(10),))
    repository = RiskRepository()
    engine = RiskEngine(
        builder=RiskBuilder(policy_version="test"),
        repository=repository,
        ranker=PriorityRanker(),
    )

    ranked = engine.run(
        (
            _chain("chain-b", severity=Severity.LOW),
            _chain("chain-a", severity=Severity.CRITICAL),
        ),
        policy,
    )

    assert [item.attack_chain_id for item in ranked] == ["chain-a", "chain-b"]
    assert [item.priority_rank for item in ranked] == [1, 2]
    assert len(repository.all()) == 2


def test_risk_engine_duplicate_run_is_ignored_by_repository():
    policy = ScoringPolicy((FixedFactor(10),))
    engine = RiskEngine(builder=RiskBuilder(policy_version="test"))
    chain = _chain("chain-a")

    first = engine.run((chain,), policy)
    second = engine.run((chain,), policy)

    assert [item.id for item in second] == [item.id for item in first]
    assert len(second) == 1
