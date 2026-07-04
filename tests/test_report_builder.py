import json

from report_builder import ReportBuilder
from thragg.core.attack_chain.attack_chain import AttackChain
from thragg.core.attack_chain.chain_edge import ChainEdge
from thragg.core.correlation.correlation import Correlation
from thragg.core.dashboard.dashboard_bundle import DashboardBundle
from thragg.core.reporting.evidence_package import EvidencePackage, EvidencePackageManifest
from thragg.core.executive.executive_assessment import ExecutiveAssessment
from thragg.core.foundation.finding import Confidence, Severity
from thragg.core.executive.framework_snapshot import FrameworkSnapshot
from thragg.core.executive.framework_statistics import CountMetric, FrameworkStatistics
from thragg.core.executive.observation import Observation, ObservationCategory
from thragg.core.risk.risk_assessment import RiskAssessment
from thragg.core.risk.risk_contribution import RiskContribution
from thragg.core.risk.risk_level import RiskLevel
from thragg.core.executive.security_posture import SecurityPosture
from thragg.core.shared.traceability_map import TraceabilityMap


GENERATED_AT = "2026-07-04T00:00:00Z"


def _risk(
    risk_id: str,
    score: int,
    level: RiskLevel,
    priority_rank: int | None,
) -> RiskAssessment:
    return RiskAssessment(
        id=risk_id,
        attack_chain_id=f"chain-{risk_id}",
        score=score,
        risk_level=level,
        contributions=(
            RiskContribution(
                id=f"contrib-{risk_id}",
                factor_name="ExistingFactor",
                score=score,
                max_contribution=100,
                reason="Framework supplied score.",
                source="risk-engine",
            ),
        ),
        summary=f"{risk_id} summary",
        recommendation=f"{risk_id} recommendation",
        created_at=GENERATED_AT,
        policy_version="m7-policy",
        priority_rank=priority_rank,
    )


def _chain() -> AttackChain:
    return AttackChain(
        id="chain-1",
        title="Public SSH to privileged account",
        description="Framework supplied chain.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        entry_point="internet",
        target="admin",
        timeline=({"stage": "INITIAL_ACCESS", "correlation_id": "corr-1"},),
        correlations=("corr-1",),
        chain_edges=(
            ChainEdge(
                from_correlation_id="corr-1",
                to_correlation_id="corr-2",
                shared_entity_id="host-1",
                shared_entity_type="HOST",
                affinity_score=2,
                reason="Shared host",
            ),
        ),
        entities=("host-1",),
        relationships=("rel-1",),
        supporting_findings=("finding-1",),
        recommendations=("Restrict SSH.",),
        created_at=GENERATED_AT,
    )


def _correlation() -> Correlation:
    return Correlation(
        id="corr-1",
        rule_id="rule-1",
        title="Public SSH",
        description="Framework supplied correlation.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        recommendation="Restrict SSH.",
        mitre=("T1021.004",),
        category="Initial Access",
        tags=("ssh",),
        timestamp=GENERATED_AT,
        matched_entities=({"id": "host-1"},),
        matched_relationships=("rel-1",),
        supporting_findings=("finding-1",),
        correlation_explanation={"reason": "public service"},
    )


def _snapshot() -> FrameworkSnapshot:
    return FrameworkSnapshot(
        risk_assessments=(
            _risk("risk-lower-priority", 98, RiskLevel.CRITICAL, 2),
            _risk("risk-top", 75, RiskLevel.HIGH, 1),
            _risk("risk-unranked", 99, RiskLevel.CRITICAL, None),
        ),
        attack_chains=(_chain(),),
        correlations=(_correlation(),),
        finding_count=7,
        entity_count=5,
        resolved_entity_count=4,
        relationship_count=3,
        snapshot_version="m8-snapshot-v1",
        generated_at=GENERATED_AT,
    )


def _assessment() -> ExecutiveAssessment:
    return ExecutiveAssessment(
        id="exec-test",
        summary="Environment has one high-risk initial access path.",
        observations=(
            Observation(
                id="obs-1",
                category=ObservationCategory.EXPOSURE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                text="Public access creates a credible initial access path.",
                supporting_object_ids=("risk-top", "chain-1", "corr-1"),
            ),
        ),
        recommendations=("Restrict SSH.", "Review privileged accounts."),
        statistics=FrameworkStatistics(
            total_findings=7,
            total_entities=5,
            total_relationships=3,
            total_correlations=1,
            total_attack_chains=1,
            risk_counts=(
                CountMetric(RiskLevel.CRITICAL.value, 2),
                CountMetric(RiskLevel.HIGH.value, 1),
            ),
            top_entity_types=(CountMetric("HOST", 3), CountMetric("USER", 2)),
            top_attack_stages=(CountMetric("INITIAL_ACCESS", 1),),
            top_attack_categories=(CountMetric("Initial Access", 1),),
        ),
        security_posture=SecurityPosture.HIGH_RISK,
        traceability=TraceabilityMap(
            observation_to_risks=(("obs-1", ("risk-top",)),),
            observation_to_attack_chains=(("obs-1", ("chain-1",)),),
            observation_to_correlations=(("obs-1", ("corr-1",)),),
            recommendation_to_observations=(("Restrict SSH.", ("obs-1",)),),
        ),
        engine_version="m8-foundation",
        generated_at=GENERATED_AT,
    )


def _evidence_package() -> EvidencePackage:
    manifest = EvidencePackageManifest(
        package_id="evidence-existing",
        generated_at=GENERATED_AT,
        engine_version="m9-report-engine",
        thragg_version="1.0",
        files=("report.md", "manifest.json"),
        snapshot_summary=(("findings", "7"),),
    )
    return EvidencePackage(
        id="pkg-existing",
        manifest=manifest,
        output_directory="/tmp/evidence-existing",
        files_written=("report.md", "manifest.json"),
        generated_at=GENERATED_AT,
        framework_version="1.0",
    )


def _dashboard_bundle() -> DashboardBundle:
    return DashboardBundle(
        id="dash-existing",
        html_file="dashboard.html",
        data_snapshot=(("risks", "3"),),
        generated_at=GENERATED_AT,
        engine_version="m10-dashboard",
    )


def test_report_builder_writes_markdown_html_json_and_manifest(tmp_path):
    package = ReportBuilder().build(
        _assessment(),
        _snapshot(),
        str(tmp_path),
        evidence_package=_evidence_package(),
        dashboard_bundle=_dashboard_bundle(),
        generated_at=GENERATED_AT,
    )

    assert package.files_written == (
        "report.md",
        "report.html",
        "report.json",
        "manifest.json",
    )
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "manifest.json").exists()


def test_report_builder_output_is_deterministic(tmp_path):
    builder = ReportBuilder()
    builder.build(_assessment(), _snapshot(), str(tmp_path), generated_at=GENERATED_AT)
    first = {
        name: (tmp_path / name).read_text(encoding="utf-8")
        for name in ("report.md", "report.html", "report.json", "manifest.json")
    }

    builder.build(_assessment(), _snapshot(), str(tmp_path), generated_at=GENERATED_AT)

    assert first == {
        name: (tmp_path / name).read_text(encoding="utf-8")
        for name in ("report.md", "report.html", "report.json", "manifest.json")
    }


def test_report_builder_orders_top_risks_by_existing_priority_rank(tmp_path):
    ReportBuilder().build(
        _assessment(),
        _snapshot(),
        str(tmp_path),
        generated_at=GENERATED_AT,
    )

    markdown = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert markdown.index("risk-top") < markdown.index("risk-lower-priority")
    assert markdown.index("risk-lower-priority") < markdown.index("risk-unranked")

    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert [risk["id"] for risk in data["top_risks"]] == [
        "risk-top",
        "risk-lower-priority",
        "risk-unranked",
    ]


def test_report_builder_renders_versions_summary_recommendations_and_statistics(tmp_path):
    ReportBuilder(
        framework_version="1.0-test",
        engine_version="report-builder-test",
    ).build(
        _assessment(),
        _snapshot(),
        str(tmp_path),
        evidence_package=_evidence_package(),
        dashboard_bundle=_dashboard_bundle(),
        generated_at=GENERATED_AT,
    )

    markdown = (tmp_path / "report.md").read_text(encoding="utf-8")
    data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))

    assert "## Executive Summary" in markdown
    assert "Environment has one high-risk initial access path." in markdown
    assert "- Restrict SSH." in markdown
    assert "- Findings: 7" in markdown
    assert "- Top entity types: HOST=3, USER=2" in markdown
    assert "- framework_version: 1.0-test" in markdown
    assert "- engine_version: report-builder-test" in markdown
    assert "- snapshot_version: m8-snapshot-v1" in markdown
    assert "- generated_at: 2026-07-04T00:00:00Z" in markdown
    assert "- Package ID: pkg-existing" in markdown
    assert "- Dashboard ID: dash-existing" in markdown

    assert data["version_information"] == {
        "engine_version": "report-builder-test",
        "framework_version": "1.0-test",
        "generated_at": GENERATED_AT,
        "intelligence_engine_version": "m8-foundation",
        "snapshot_version": "m8-snapshot-v1",
    }
    assert data["statistics"]["total_findings"] == 7
    assert data["recommendations"] == [
        "Restrict SSH.",
        "Review privileged accounts.",
    ]


def test_report_builder_does_not_mutate_framework_objects(tmp_path):
    assessment = _assessment()
    snapshot = _snapshot()
    before = (assessment.to_dict(), snapshot.to_dict())

    ReportBuilder().build(
        assessment,
        snapshot,
        str(tmp_path),
        generated_at=GENERATED_AT,
    )

    assert (assessment.to_dict(), snapshot.to_dict()) == before
