import json

from thragg.core.correlation.correlation import Correlation
from thragg.core.executive.executive_assessment import ExecutiveAssessment
from thragg.core.foundation.finding import Confidence, Severity
from thragg.core.executive.framework_snapshot import FrameworkSnapshot
from thragg.core.executive.framework_statistics import CountMetric, FrameworkStatistics
from thragg.core.reporting.html_renderer import HtmlRenderer
from thragg.core.reporting.json_renderer import JsonRenderer
from thragg.core.reporting.markdown_renderer import MarkdownRenderer
from thragg.core.executive.observation import Observation, ObservationCategory
from thragg.core.reporting.report_engine import ReportEngine
from thragg.core.risk.risk_level import RiskLevel
from thragg.core.shared.version import FRAMEWORK_VERSION
from thragg.core.executive.security_posture import SecurityPosture
from thragg.core.shared.traceability_map import TraceabilityMap


def _snapshot() -> FrameworkSnapshot:
    return FrameworkSnapshot(
        risk_assessments=(),
        attack_chains=(),
        correlations=(
            Correlation(
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
                timestamp="2026-07-04T00:00:00Z",
                matched_entities=({"id": "host-1"},),
                matched_relationships=("rel-1",),
                supporting_findings=("finding-1",),
                correlation_explanation={"risk": "public service"},
            ),
        ),
        finding_count=3,
        entity_count=2,
        resolved_entity_count=1,
        relationship_count=1,
        snapshot_version="m8-snapshot-v1",
        generated_at="2026-07-04T00:00:00Z",
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
                supporting_object_ids=("risk-1", "chain-1", "corr-1"),
            ),
        ),
        recommendations=("Restrict SSH.",),
        statistics=FrameworkStatistics(
            total_findings=3,
            total_entities=2,
            total_relationships=1,
            total_correlations=1,
            total_attack_chains=0,
            risk_counts=(CountMetric(RiskLevel.HIGH.value, 1),),
            top_entity_types=(CountMetric("HOST", 2),),
            top_attack_stages=(CountMetric("INITIAL_ACCESS", 1),),
            top_attack_categories=(CountMetric("Initial Access", 1),),
        ),
        security_posture=SecurityPosture.HIGH_RISK,
        traceability=TraceabilityMap(
            observation_to_risks=(("obs-1", ("risk-1",)),),
            observation_to_attack_chains=(("obs-1", ("chain-1",)),),
            observation_to_correlations=(("obs-1", ("corr-1",)),),
            recommendation_to_observations=(("Restrict SSH.", ("obs-1",)),),
        ),
        engine_version="m8-foundation",
        generated_at="2026-07-04T00:00:00Z",
    )


def test_renderers_return_text_without_creating_intelligence():
    assessment = _assessment()
    snapshot = _snapshot()

    markdown = MarkdownRenderer().render(assessment, snapshot)
    data = json.loads(JsonRenderer().render(assessment, snapshot))
    html = HtmlRenderer().render(assessment, snapshot)

    assert "# THRAGG Executive Assessment" in markdown
    assert "- **HIGH** Public access creates" in markdown
    assert data["executive_assessment"]["id"] == "exec-test"
    assert data["framework_snapshot"]["finding_count"] == 3
    assert "<!doctype html>" in html
    assert "Security Posture" in html
    assert MarkdownRenderer.content_type == "text/markdown"
    assert HtmlRenderer.content_type == "text/html"
    assert JsonRenderer.content_type == "application/json"


def test_report_engine_registers_and_runs_every_renderer(tmp_path):
    class TextRenderer:
        format = "txt"
        content_type = "text/plain"

        def render(self, executive_assessment, framework_snapshot):
            return f"{executive_assessment.id}:{framework_snapshot.finding_count}"

    engine = ReportEngine((TextRenderer(),))

    package = engine.publish(
        _assessment(),
        _snapshot(),
        str(tmp_path),
        generated_at="2026-07-04T00:00:00Z",
    )

    assert len(engine.renderers) == 1
    assert (tmp_path / "report.txt").read_text(encoding="utf-8") == "exec-test:3"
    assert package.files_written == ("report.txt", "manifest.json")
    assert package.framework_version == FRAMEWORK_VERSION
    assert package.manifest.thragg_version == FRAMEWORK_VERSION


def test_report_engine_creates_manifest_package_and_reports(tmp_path):
    engine = ReportEngine((MarkdownRenderer(), JsonRenderer(), HtmlRenderer()))

    package = engine.publish(
        _assessment(),
        _snapshot(),
        str(tmp_path),
        generated_at="2026-07-04T00:00:00Z",
    )
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))

    assert package.manifest.package_id == "evidence-exec-test"
    assert package.files_written == (
        "report.md",
        "report.json",
        "report.html",
        "manifest.json",
    )
    assert package.framework_version == "1.0"
    assert manifest["files"] == list(package.files_written)
    assert manifest["snapshot_summary"] == [
        ["findings", "3"],
        ["entities", "2"],
        ["resolved_entities", "1"],
        ["relationships", "1"],
    ]
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.html").exists()


def test_report_engine_outputs_are_stable(tmp_path):
    engine = ReportEngine((MarkdownRenderer(), JsonRenderer(), HtmlRenderer()))
    kwargs = dict(
        executive_assessment=_assessment(),
        framework_snapshot=_snapshot(),
        output_directory=str(tmp_path),
        generated_at="2026-07-04T00:00:00Z",
    )

    first = engine.publish(**kwargs)
    first_json = (tmp_path / "report.json").read_text(encoding="utf-8")
    first_manifest = (tmp_path / "manifest.json").read_text(encoding="utf-8")
    second = engine.publish(**kwargs)

    assert first.id == second.id
    assert first.to_dict() == second.to_dict()
    assert first_json == (tmp_path / "report.json").read_text(encoding="utf-8")
    assert first_manifest == (tmp_path / "manifest.json").read_text(encoding="utf-8")
