from thragg.core import (
    CorrelationEngine,
    CorrelationRule,
    EntityType,
    RelationshipPattern,
    RelationshipInferencer,
    RelationshipType,
    correlation_rule_from_dict,
    relationship_inference_rule_from_dict,
)
from thragg.core.foundation.finding import Confidence, Severity
import pytest


def _contract(module: str, finding: dict) -> dict:
    return {
        "metadata": {"module": module},
        "summary": {},
        "details": {"findings": [finding]},
        "artifacts": {},
        "errors": [],
    }


def _host_exposes_rule() -> CorrelationRule:
    return CorrelationRule(
        rule_id="CORR-HOST-EXPOSES-SERVICE",
        title="Host exposes service",
        description="A host exposes a network service.",
        version="1.0",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        mitre=(),
        category="Correlation",
        tags=("foundation",),
        recommendation="Review exposed service.",
        patterns=(
            RelationshipPattern(
                "HOST",
                EntityType.HOST,
                RelationshipType.EXPOSES,
                "SERVICE",
                EntityType.SERVICE,
            ),
        ),
    )


def test_contract_pipeline_builds_registry_graph_and_correlation():
    engine = CorrelationEngine((_host_exposes_rule(),))
    contract = _contract(
        "nmap",
        {
            "rule_id": "NMAP-192.168.56.20-22",
            "title": "Open Port 22/tcp (ssh)",
            "severity": "Medium",
            "confidence": "High",
            "category": "Network Reconnaissance",
            "asset": "192.168.56.20",
            "port": 22,
            "service": "ssh",
            "evidence": {"port": 22, "service_name": "ssh"},
        },
    )

    correlations = engine.run_contracts((contract,))
    relationships = engine.relationship_repository.list()

    assert len(engine.entity_registry.repository.list()) == 2
    assert len(relationships) == 1
    assert relationships[0].relationship_type is RelationshipType.EXPOSES
    assert relationships[0].source_module == "nmap"
    assert relationships[0].supporting_findings == ("NMAP-192.168.56.20-22",)
    assert relationships[0].confidence_contribution == 1.0
    assert engine.graph.neighbors(relationships[0].source_entity_id) == (
        relationships[0].target_entity_id,
    )
    assert [correlation.rule_id for correlation in correlations] == [
        "CORR-HOST-EXPOSES-SERVICE"
    ]
    assert correlations[0].to_dict()["correlation_id"] == correlations[0].id


def test_entity_registry_deduplicates_same_host_across_modules_before_graphing():
    engine = CorrelationEngine(())
    nmap_contract = _contract(
        "nmap",
        {
            "rule_id": "NMAP-HOST",
            "title": "Host observed",
            "severity": "Low",
            "confidence": "High",
            "category": "Network",
            "asset": "192.168.56.20",
            "evidence": {},
        },
    )
    logs_contract = _contract(
        "logs",
        {
            "rule_id": "LOG-HOST",
            "title": "Host login observed",
            "severity": "Low",
            "confidence": "High",
            "category": "Authentication",
            "asset": "192.168.56.20",
            "evidence": {"ip": "192.168.56.20"},
        },
    )

    engine.run_contracts((nmap_contract, logs_contract))
    hosts = [
        entity
        for entity in engine.entity_registry.repository.list()
        if entity.entity_type is EntityType.HOST
    ]

    assert len(hosts) == 1
    assert hosts[0].primary_identifier == "192.168.56.20"
    assert hosts[0].source_modules == ["logs", "nmap"]


def test_rules_can_be_constructed_from_plain_data_without_engine_changes():
    inference_rule = relationship_inference_rule_from_dict(
        {
            "rule_id": "REL-HOST-EXPOSES-SERVICE",
            "source_entity_type": "HOST",
            "relationship_type": "EXPOSES",
            "target_entity_type": "SERVICE",
            "required_evidence_keys": ["port"],
            "confidence": "HIGH",
        }
    )
    correlation_rule = correlation_rule_from_dict(
        {
            "rule_id": "CORR-DATA-DRIVEN-HOST-EXPOSES",
            "title": "Host exposes service",
            "description": "A host exposes a service.",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "patterns": [
                {
                    "source_variable": "HOST",
                    "source_entity_type": "HOST",
                    "relationship_type": "EXPOSES",
                    "target_variable": "SERVICE",
                    "target_entity_type": "SERVICE",
                }
            ],
        }
    )
    engine = CorrelationEngine(
        (correlation_rule,),
        inferencer=RelationshipInferencer((inference_rule,)),
    )
    contract = _contract(
        "nmap",
        {
            "rule_id": "NMAP-SSH",
            "title": "Open SSH",
            "severity": "Medium",
            "confidence": "High",
            "category": "Network",
            "asset": "192.168.56.20",
            "port": 22,
            "service": "ssh",
        },
    )

    correlations = engine.run_contracts((contract,))

    assert [item.rule_id for item in correlations] == [
        "CORR-DATA-DRIVEN-HOST-EXPOSES"
    ]


def test_contract_pipeline_rejects_malformed_contract_sections():
    engine = CorrelationEngine(())

    with pytest.raises(TypeError, match="contract must be a dict"):
        engine.run_contracts(("not-a-contract",))

    with pytest.raises(TypeError, match="metadata must be dict"):
        engine.run_contracts(
            (
                {
                    "metadata": [],
                    "summary": {},
                    "details": {"findings": []},
                    "artifacts": {},
                    "errors": [],
                },
            )
        )

    with pytest.raises(TypeError, match="details.findings entries"):
        engine.run_contracts(
            (
                {
                    "metadata": {"module": "nmap"},
                    "summary": {},
                    "details": {"findings": ["bad-finding"]},
                    "artifacts": {},
                    "errors": [],
                },
            )
        )
