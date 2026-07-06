import json

import pytest

from thragg.core.dashboard import DashboardGenerator
from thragg.core.reporting import (
    ConsoleRenderer,
    HTMLRenderer,
    JSONRenderer,
    MarkdownRenderer,
    ReportEngine,
    ReportModel,
    ReportRepository,
    ReportType,
    ReportValidationError,
    ReportValidator,
)


def _assessment():
    return {
        "assessment_id": "exec-1",
        "security_posture": "Needs Attention",
        "overall_summary": "Executive summary.",
        "business_impact": [{"summary": "Business impact."}],
        "top_risks": [
            {
                "risk_id": "risk-1",
                "risk_level": "HIGH",
                "score": 80,
                "summary": "Risk summary.",
                "suggested_action": "Fix it.",
            }
        ],
        "top_priorities": ["Fix exposed identity path"],
        "executive_recommendations": [
            {
                "id": "rec-1",
                "title": "Reduce exposure",
                "description": "Reduce externally reachable paths.",
                "priority": "High",
                "expected_benefit": "Lower risk.",
            }
        ],
        "assessment_scope": {
            "modules_run": ["nmap"],
            "modules_skipped": [],
            "evidence_files": ["scan.xml"],
            "assessment_limitations": [],
            "assessment_time": "2026-07-06T00:00:00+00:00",
        },
        "metadata": {"modules_used": ["nmap"]},
        "risk_distribution": [{"risk_level": "HIGH", "count": 1}],
        "traceability": [
            {
                "recommendation_id": "rec-1",
                "risk_assessment_id": "risk-1",
                "attack_chain_id": "chain-1",
                "correlation_id": "corr-1",
                "finding_ids": ["finding-1"],
                "evidence_files": ["scan.xml"],
                "chain_depth": 2,
            }
        ],
    }


def test_reporting_engine_builds_valid_report_model():
    report = ReportEngine().generate(_assessment(), ReportType.EXECUTIVE, "run-1")

    assert isinstance(report, ReportModel)
    assert report.metadata.report_version
    assert report.traceability_appendix[0].chain_depth == 2
    assert ReportValidator().validate(report).valid


def test_repository_helpers_and_renderers_use_report_model(tmp_path):
    report = ReportEngine().generate(_assessment(), ReportType.EXECUTIVE, "run-1")
    repository = ReportRepository()
    repository.add(report)

    assert repository.latest() == report
    assert repository.by_type(ReportType.EXECUTIVE) == [report]
    assert "# THRAGG" in MarkdownRenderer().render(report)
    assert "<html" in HTMLRenderer().render(report)
    assert json.loads(JSONRenderer().render(report))["id"] == report.id
    assert "THRAGG Assessment Complete" in ConsoleRenderer().render(report)

    bundle = DashboardGenerator().generate(report, str(tmp_path / "dashboard.html"))
    assert bundle.html_file.endswith("dashboard.html")


def test_validator_rejects_untraced_recommendation():
    report = ReportEngine().generate(_assessment(), ReportType.EXECUTIVE, "run-1")
    report.traceability_appendix.clear()

    result = ReportValidator().validate(report)

    assert not result.valid
    assert isinstance(result.errors[0], ReportValidationError)
