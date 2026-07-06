from pathlib import Path

from thragg.core.attack_chain import (
    AttackChainEngine,
    AttackChainRuleRepository,
    AttackStep,
)
from thragg.core.correlation.correlation import Correlation
from thragg.core.correlation.correlation_repository import CorrelationRepository
from thragg.core.correlation.correlation_rule import AttackStage
from thragg.core.dashboard import DashboardGenerator, DashboardSection
from thragg.core.executive import ExecutiveAssessmentBuilder, FrameworkSnapshot
from thragg.core.foundation.finding import Confidence, Severity
from thragg.core.risk import (
    ChainLengthFactor,
    ConfidenceFactor,
    CriticalAssetFactor,
    EnvironmentRiskAssessment,
    ExposureFactor,
    MITREFactor,
    RiskEngine,
    ScoringPolicy,
    SeverityFactor,
)


def _correlation(
    correlation_id: str,
    stage: AttackStage,
    entity: str,
    *,
    mitre: tuple[str, ...] = (),
) -> Correlation:
    return Correlation(
        id=correlation_id,
        rule_id=f"rule-{correlation_id}",
        title=f"Correlation {correlation_id}",
        description="Correlated intelligence.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        recommendation="Reduce exposure and review identity controls.",
        mitre=mitre,
        category="Identity Exposure",
        tags=("identity",),
        timestamp="2026-07-04T00:00:00Z",
        matched_entities=(
            {"id": entity, "entity_type": "HOST"},
            {"id": "user-admin", "entity_type": "USER"},
        ),
        matched_relationships=(f"rel-{correlation_id}",),
        supporting_findings=(f"finding-{correlation_id}",),
        correlation_explanation={"stage": stage.value},
    )


def _repository(*correlations: Correlation) -> CorrelationRepository:
    repository = CorrelationRepository()
    for correlation in correlations:
        repository.add(correlation)
    return repository


def test_intelligence_layer_pipeline_uses_correlations_only(tmp_path):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        """
        {
          "rules": [
            {
              "rule_id": "TEST-CHAIN-RULE",
              "title": "Test path",
              "description": "Test initial access to credential access.",
              "stage_sequence": ["INITIAL_ACCESS", "CREDENTIAL_ACCESS"]
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    rules = AttackChainRuleRepository.from_json(Path(rules_path))
    correlations = (
        _correlation("corr-a", AttackStage.INITIAL_ACCESS, "host-1", mitre=("T1021.004",)),
        _correlation("corr-b", AttackStage.CREDENTIAL_ACCESS, "host-1", mitre=("T1078",)),
    )

    chains = AttackChainEngine().run(_repository(*correlations))
    assert chains[0].steps[0].stage == "INITIAL_ACCESS"
    assert isinstance(chains[0].steps[0], AttackStep)
    assert rules[0].matches(correlations) is True

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
    risk_engine = RiskEngine()
    risks = risk_engine.run(chains, policy)
    environment = risk_engine.assess_environment(
        risks,
        chains,
        "2026-07-04T00:00:00Z",
    )

    assert isinstance(environment, EnvironmentRiskAssessment)
    assert environment.overall_score >= risks[0].score
    assert "overall_score = min(100" in environment.formula

    snapshot = FrameworkSnapshot(
        risk_assessments=risks,
        attack_chains=chains,
        correlations=correlations,
        finding_count=2,
        entity_count=2,
        resolved_entity_count=2,
        relationship_count=2,
        snapshot_version="test",
        generated_at="2026-07-04T00:00:00Z",
    )
    executive = ExecutiveAssessmentBuilder().build(
        snapshot,
        generated_at="2026-07-04T00:00:00Z",
    )
    sections = DashboardGenerator().build_sections(executive, snapshot)

    assert executive.to_dict()["executive_summary"] == executive.summary
    assert isinstance(sections[0], DashboardSection)
    assert sections[0].section_id == "risk-overview"
