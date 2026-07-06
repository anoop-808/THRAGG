from thragg.core.executive import AssessmentScope, ExecutiveEngine, SecurityPosture
from thragg.core.risk.risk_assessment import RiskAssessment
from thragg.core.risk.risk_contribution import RiskContribution
from thragg.core.risk.risk_level import RiskLevel


def _risk(**overrides) -> RiskAssessment:
    contribution = RiskContribution(
        id="contribution-1",
        factor_name="exposure",
        score=80,
        max_contribution=100,
        reason="SSH exposure",
        source="risk_engine",
    )
    defaults = dict(
        id="risk-1",
        attack_chain_id="chain-1",
        score=80,
        risk_level=RiskLevel.HIGH,
        contributions=(contribution,),
        summary="SSH exposure affects Admin Account.",
        recommendation="Restrict SSH exposure.",
        created_at="2026-07-06T00:00:00Z",
        policy_version="m7-foundation",
        priority_rank=1,
    )
    defaults.update(overrides)
    return RiskAssessment(**defaults)


def test_executive_engine_consumes_risks_only_and_builds_assessment():
    scope = AssessmentScope(
        modules_run=("nmap",),
        modules_skipped=("zap",),
        evidence_files=("nmap.xml",),
        assessment_limitations=("Only supplied risk assessments were interpreted.",),
        assessment_time="2026-07-06T00:00:00Z",
    )

    assessment = ExecutiveEngine().run((_risk(),), scope)

    assert assessment.security_posture is SecurityPosture.POOR
    assert assessment.assessment_scope.evidence_files == ("nmap.xml",)
    assert assessment.top_risks[0].summary == (
        "Remote Administrative Access exposure affects Privileged Identity."
    )
    assert assessment.business_impact[0].impact == (
        "Privileged identities may be exposed."
    )
    assert assessment.executive_recommendations[0].id == "REC-IAM-001"
    assert assessment.to_dict()["metadata"]["input_contract"] == "RiskAssessment[]"
