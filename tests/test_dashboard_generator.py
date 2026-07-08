import json
import re
import subprocess

from thragg.core.attack_chain.attack_chain import AttackChain
from thragg.core.attack_chain.chain_edge import ChainEdge
from thragg.core.foundation.core_relationship_fact import RelationshipFact, RelationshipType
from thragg.core.correlation.correlation import Correlation
from thragg.core.dashboard.dashboard_generator import DashboardGenerator
from thragg.core.foundation.entity import Entity
from thragg.core.executive.executive_assessment import ExecutiveAssessment
from thragg.core.foundation.finding import Confidence, EntityType, Finding, Severity
from thragg.core.executive.framework_snapshot import FrameworkSnapshot
from thragg.core.executive.framework_statistics import CountMetric, FrameworkStatistics
from thragg.core.executive.observation import Observation, ObservationCategory
from thragg.core.foundation.resolved_entity import ResolvedEntity
from thragg.core.risk.risk_assessment import RiskAssessment
from thragg.core.risk.risk_contribution import RiskContribution
from thragg.core.risk.risk_level import RiskLevel
from thragg.core.executive.security_posture import SecurityPosture
from thragg.core.shared.traceability_map import TraceabilityMap


def _finding() -> Finding:
    return Finding(
        id="finding-1",
        title="SSH exposed",
        description="SSH is exposed to the internet.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="Network Exposure",
        type="SSH_EXPOSED",
        source_module="nmap",
        source_rule="rule-1",
        entity_type=EntityType.HOST,
        asset="10.0.0.5",
        observed_at="2026-07-04T00:00:00Z",
        recommendation="Restrict SSH.",
        mitre=["T1021.004"],
        tags=["ssh"],
        evidence={"port": 22},
    )


def _entity() -> Entity:
    return Entity(
        id="entity-1",
        type=EntityType.HOST,
        primary_identifier="10.0.0.5",
        source_module="nmap",
        source_finding="finding-1",
        confidence=Confidence.HIGH,
    )


def _resolved_entity() -> ResolvedEntity:
    return ResolvedEntity(
        id="resolved-1",
        entity_type=EntityType.HOST,
        primary_identifier="10.0.0.5",
        source_entities=["entity-1"],
        source_findings=["finding-1"],
        source_modules=["nmap"],
    )


def _relationship() -> RelationshipFact:
    return RelationshipFact(
        id="rel-1",
        source_entity_id="resolved-1",
        source_entity_type=EntityType.HOST,
        target_entity_id="resolved-2",
        target_entity_type=EntityType.SERVICE,
        relationship_type=RelationshipType.EXPOSES,
        source_module="nmap",
        source_rule="rule-1",
        confidence=Confidence.HIGH,
        supporting_findings=("finding-1",),
        observed_at="2026-07-04T00:00:00Z",
    )


def _correlation() -> Correlation:
    return Correlation(
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
        matched_entities=({"id": "resolved-1"},),
        matched_relationships=("rel-1",),
        supporting_findings=("finding-1",),
        correlation_explanation={"reason": "public service"},
    )


def _chain() -> AttackChain:
    return AttackChain(
        id="chain-1",
        title="Initial access chain",
        description="A deterministic chain.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        entry_point="corr-1",
        target="corr-1",
        timeline=({"stage": "INITIAL_ACCESS", "correlation_id": "corr-1"},),
        correlations=("corr-1",),
        chain_edges=(
            ChainEdge("corr-1", "corr-2", "resolved-1", "HOST", 2, "Shared host"),
        ),
        entities=("resolved-1",),
        relationships=("rel-1",),
        supporting_findings=("finding-1",),
        recommendations=("Restrict SSH.",),
        created_at="2026-07-04T00:00:00Z",
    )


def _risk() -> RiskAssessment:
    return RiskAssessment(
        id="risk-1",
        attack_chain_id="chain-1",
        score=30,
        risk_level=RiskLevel.HIGH,
        contributions=(
            RiskContribution(
                id="contribution-1",
                factor_name="severity",
                score=30,
                max_contribution=40,
                reason="HIGH chain severity",
                source="attack_chain.severity",
            ),
        ),
        summary="High risk chain.",
        recommendation="Review the chain.",
        created_at="2026-07-04T00:00:00Z",
        policy_version="m7-foundation",
    )


def _snapshot() -> FrameworkSnapshot:
    return FrameworkSnapshot(
        risk_assessments=(_risk(),),
        attack_chains=(_chain(),),
        correlations=(_correlation(),),
        finding_count=1,
        entity_count=1,
        resolved_entity_count=1,
        relationship_count=1,
        snapshot_version="m8-snapshot-v1",
        generated_at="2026-07-04T00:00:00Z",
    )


def _assessment() -> ExecutiveAssessment:
    return ExecutiveAssessment(
        id="exec-1",
        summary="Environment has one high-risk path.",
        observations=(
            Observation(
                id="obs-1",
                category=ObservationCategory.EXPOSURE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                text="Public SSH creates an initial access path.",
                supporting_object_ids=("risk-1", "chain-1", "corr-1"),
            ),
        ),
        recommendations=("Restrict SSH.",),
        statistics=FrameworkStatistics(
            total_findings=1,
            total_entities=1,
            total_relationships=1,
            total_correlations=1,
            total_attack_chains=1,
            risk_counts=(CountMetric("HIGH", 1),),
            top_entity_types=(CountMetric("HOST", 1),),
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


def _embedded_json(html: str) -> dict:
    match = re.search(
        r'<script id="thragg-dashboard-data" type="application/json">(.*?)</script>',
        html,
    )
    assert match
    return json.loads(match.group(1))


def _embedded_json_text(html: str) -> str:
    match = re.search(
        r'<script id="thragg-dashboard-data" type="application/json">(.*?)</script>',
        html,
    )
    assert match
    return match.group(1)


def _bootstrap_script(html: str) -> str:
    match = re.search(r"<script>\s*(try \{.*?window\.THRAGG_DATA.*?)</script>", html, re.S)
    assert match
    return match.group(1)


def test_dashboard_generator_writes_self_contained_html_and_bundle(tmp_path):
    output = tmp_path / "dashboard.html"
    bundle = DashboardGenerator().generate(
        _assessment(),
        _snapshot(),
        str(output),
        relationships=(_relationship(),),
        resolved_entities=(_resolved_entity(),),
        entities=(_entity(),),
        findings=(_finding(),),
        generated_at="2026-07-04T00:00:00Z",
    )

    html = output.read_text(encoding="utf-8")
    data = _embedded_json(html)

    assert bundle.html_file == str(output)
    assert bundle.data_snapshot == (
        ("findings", "1"),
        ("entities", "1"),
        ("resolved_entities", "1"),
        ("relationships", "1"),
    )
    assert "<!DOCTYPE html>" in html
    assert "React" not in html
    assert data["executive_assessment"]["id"] == "exec-1"
    assert data["framework_snapshot"]["finding_count"] == 1
    assert data["risk_assessments"][0]["id"] == "risk-1"
    assert data["attack_chains"][0]["id"] == "chain-1"
    assert data["correlations"][0]["id"] == "corr-1"
    assert data["relationships"][0]["id"] == "rel-1"
    assert data["findings"][0]["evidence"] == {"port": 22}
    assert "report_model" not in data


def test_dashboard_contains_all_views_and_payload_contract(tmp_path):
    output = tmp_path / "dashboard.html"
    DashboardGenerator().generate(
        _assessment(),
        _snapshot(),
        str(output),
        relationships=(_relationship(),),
        resolved_entities=(_resolved_entity(),),
        entities=(_entity(),),
        findings=(_finding(),),
        generated_at="2026-07-04T00:00:00Z",
    )

    html = output.read_text(encoding="utf-8")
    data = _embedded_json(html)

    assert data["views"] == [
        "EXECUTIVE_SUMMARY",
        "RISK_PRIORITY",
        "ATTACK_CHAINS",
        "CORRELATIONS",
        "KNOWLEDGE_GRAPH",
        "MITRE_MATRIX",
        "EVIDENCE_EXPLORER",
    ]
    assert data["explain_order"] == [
        "ExecutiveAssessment",
        "RiskAssessment",
        "AttackChain",
        "Correlation",
        "Relationship",
        "ResolvedEntity",
        "Entity",
        "Finding",
    ]
    assert {"executive_assessment", "framework_snapshot", "risk_assessments"} <= data.keys()


def test_dashboard_output_is_deterministic(tmp_path):
    output = tmp_path / "dashboard.html"
    generator = DashboardGenerator()
    kwargs = dict(
        executive_assessment=_assessment(),
        framework_snapshot=_snapshot(),
        output_file=str(output),
        relationships=(_relationship(),),
        resolved_entities=(_resolved_entity(),),
        entities=(_entity(),),
        findings=(_finding(),),
        generated_at="2026-07-04T00:00:00Z",
    )

    first = generator.generate(**kwargs)
    first_html = output.read_text(encoding="utf-8")
    second = generator.generate(**kwargs)

    assert first.id == second.id
    assert first.to_dict() == second.to_dict()
    assert first_html == output.read_text(encoding="utf-8")


def test_dashboard_bootstrap_assigns_embedded_json_to_thragg_data(tmp_path):
    output = tmp_path / "dashboard.html"
    DashboardGenerator().generate(
        _assessment(),
        _snapshot(),
        str(output),
        relationships=(_relationship(),),
        resolved_entities=(_resolved_entity(),),
        entities=(_entity(),),
        findings=(_finding(),),
        generated_at="2026-07-04T00:00:00Z",
    )

    html = output.read_text(encoding="utf-8")
    embedded_json = _embedded_json_text(html)
    bootstrap = _bootstrap_script(html)
    node_script = f"""
global.window = {{}};
global.document = {{
  getElementById: () => ({{ textContent: process.argv[1] }}),
  addEventListener: () => {{}}
}};
global.console = {{ warn: (...args) => {{ throw new Error(args.join(' ')); }} }};
{bootstrap}
if (!window.THRAGG_DATA || window.THRAGG_DATA.executive_assessment.id !== 'exec-1') {{
  process.exit(1);
}}
"""

    subprocess.run(["node", "-e", node_script, embedded_json], check=True)
    assert "__THRAGG_DASHBOARD_DATA__" not in html


def test_dashboard_handles_empty_data(tmp_path):
    output = tmp_path / "empty_dashboard.html"
    empty_snapshot = FrameworkSnapshot(
        risk_assessments=(),
        attack_chains=(),
        correlations=(),
        finding_count=0,
        entity_count=0,
        resolved_entity_count=0,
        relationship_count=0,
        snapshot_version="test",
        generated_at="2026-07-04T00:00:00Z"
    )
    empty_assessment = ExecutiveAssessment(
        id="empty-1",
        summary="No risks.",
        observations=(),
        recommendations=(),
        statistics=FrameworkStatistics(
            total_findings=0, total_entities=0, total_relationships=0,
            total_correlations=0, total_attack_chains=0, risk_counts=(),
            top_entity_types=(), top_attack_stages=(), top_attack_categories=()
        ),
        security_posture=SecurityPosture.HEALTHY,
        traceability=TraceabilityMap((),(),(),()),
        engine_version="test",
        generated_at="2026-07-04T00:00:00Z"
    )
    bundle = DashboardGenerator().generate(
        empty_assessment,
        empty_snapshot,
        str(output),
        relationships=(),
        resolved_entities=(),
        entities=(),
        findings=(),
        generated_at="2026-07-04T00:00:00Z"
    )
    
    html = output.read_text(encoding="utf-8")
    data = _embedded_json(html)
    
    assert data["framework_snapshot"]["finding_count"] == 0
    assert data["attack_chains"] == []
    assert bundle.html_file == str(output)
