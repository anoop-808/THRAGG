import pytest

from thragg.core.attack_chain.attack_chain_builder import AttackChainBuilder
from thragg.core.attack_chain.attack_chain_engine import AttackChainEngine
from thragg.core.attack_chain.attack_pattern_matcher import AttackPatternMatcher
from thragg.core.attack_chain.attack_chain_repository import AttackChainRepository
from thragg.core.attack_chain.attack_chain_schema import (
    AttackChainSchema,
    AttackChainSchemaError,
    is_valid_attack_chain,
)
from thragg.core.attack_chain.attack_step import AttackStep
from thragg.core.attack_chain.attack_template import AttackTemplate
from thragg.core.attack_chain.attack_template_repository import AttackTemplateRepository
from thragg.core.attack_chain.attack_chain_validator import (
    AttackChainValidationError,
    AttackChainValidator,
)
from thragg.core.attack_chain.relationship_traverser import RelationshipTraverser
from thragg.core.attack_chain.chain_candidate import ChainCandidate
from thragg.core.attack_chain.chain_discovery_engine import ChainDiscoveryEngine
from thragg.core.attack_chain.chain_edge import AFFINITY_WEIGHTS, ChainEdge, affinity_score
from thragg.core.attack_chain.chain_validator import ChainValidator
from thragg.core.correlation.correlation import Correlation
from thragg.core.correlation.correlation_repository import CorrelationRepository
from thragg.core.correlation.correlation_rule import AttackStage, RuleRegistry
from thragg.core.foundation.core_relationship_fact import RelationshipFact, RelationshipType
from thragg.core.foundation.finding import Confidence, EntityType, Severity
from thragg.core.foundation.relationship_graph import RelationshipGraph
from thragg.core.foundation.resolved_entity import ResolvedEntity


def _correlation(
    correlation_id: str,
    stage: AttackStage,
    timestamp: str,
    entities: tuple[tuple[str, str], ...],
    relationships: tuple[str, ...] = ("rel-1",),
    *,
    title: str | None = None,
    severity: Severity = Severity.HIGH,
    confidence: Confidence = Confidence.HIGH,
    recommendation: str | None = None,
    mitre: tuple[str, ...] = (),
    supporting_findings: tuple[str, ...] | None = None,
) -> Correlation:
    return Correlation(
        id=correlation_id,
        rule_id=f"rule-{correlation_id}",
        title=title or f"Correlation {correlation_id}",
        description="Test correlation.",
        severity=severity,
        confidence=confidence,
        recommendation=recommendation or f"Review {correlation_id}.",
        mitre=mitre,
        category="Correlation",
        tags=(),
        timestamp=timestamp,
        matched_entities=tuple(
            {"id": entity_id, "entity_type": entity_type}
            for entity_id, entity_type in entities
        ),
        matched_relationships=relationships,
        supporting_findings=supporting_findings or (f"finding-{correlation_id}",),
        correlation_explanation={"stage": stage.value},
    )


def _repository(*correlations: Correlation) -> CorrelationRepository:
    repository = CorrelationRepository()
    for correlation in correlations:
        repository.add(correlation)
    return repository


def test_affinity_scoring_and_chain_edge_generation():
    assert affinity_score("HOST") == 2
    assert affinity_score("DATABASE") == 3
    assert affinity_score(EntityType.UNKNOWN.value) == 1
    assert set(AFFINITY_WEIGHTS) == {item.value for item in EntityType}

    first = _correlation(
        "corr-a",
        AttackStage.INITIAL_ACCESS,
        "2026-07-03T00:00:00Z",
        (("host-1", "HOST"),),
    )
    second = _correlation(
        "corr-b",
        AttackStage.LATERAL_MOVEMENT,
        "2026-07-03T00:01:00Z",
        (("host-1", "HOST"),),
    )

    candidate = ChainDiscoveryEngine().discover(_repository(first, second))[0]

    assert isinstance(candidate, ChainCandidate)
    assert candidate.correlation_ids == ("corr-a", "corr-b")
    assert candidate.entities == ("host-1",)
    assert candidate.edges == (
        ChainEdge(
            from_correlation_id="corr-a",
            to_correlation_id="corr-b",
            shared_entity_id="host-1",
            shared_entity_type="HOST",
            affinity_score=2,
            reason="Shared HOST entity",
        ),
    )


def test_dfs_discovery_is_deterministic_and_keeps_components_separate():
    corr_a = _correlation(
        "corr-a",
        AttackStage.INITIAL_ACCESS,
        "2026-07-03T00:00:00Z",
        (("host-1", "HOST"),),
    )
    corr_b = _correlation(
        "corr-b",
        AttackStage.DISCOVERY,
        "2026-07-03T00:02:00Z",
        (("host-1", "HOST"), ("service-1", "SERVICE")),
    )
    corr_c = _correlation(
        "corr-c",
        AttackStage.COLLECTION,
        "2026-07-03T00:03:00Z",
        (("service-1", "SERVICE"),),
    )
    corr_d = _correlation(
        "corr-d",
        AttackStage.IMPACT,
        "2026-07-03T00:04:00Z",
        (("host-2", "HOST"),),
    )

    candidates = ChainDiscoveryEngine().discover(
        _repository(corr_d, corr_c, corr_b, corr_a)
    )

    assert [candidate.correlation_ids for candidate in candidates] == [
        ("corr-a", "corr-b", "corr-c"),
        ("corr-d",),
    ]


def test_chain_validation_rules_and_cycle_rejection():
    valid = ChainCandidate(
        correlation_ids=("corr-a", "corr-b"),
        edges=(
            ChainEdge("corr-a", "corr-b", "host-1", "HOST", 2, "Shared HOST entity"),
        ),
        entities=("host-1", "service-1"),
    )
    too_short = ChainCandidate(("corr-a",), (), ("host-1",))
    one_entity = ChainCandidate(("corr-a", "corr-b"), valid.edges, ("host-1",))
    cyclic = ChainCandidate(
        correlation_ids=("corr-a", "corr-b"),
        edges=(
            ChainEdge("corr-a", "corr-b", "host-1", "HOST", 2, "Shared HOST entity"),
            ChainEdge("corr-b", "corr-a", "host-1", "HOST", 2, "Shared HOST entity"),
        ),
        entities=("host-1", "service-1"),
    )

    validator = ChainValidator()

    assert validator.is_valid(valid) is True
    assert validator.is_valid(too_short) is False
    assert validator.is_valid(one_entity) is False
    assert validator.is_valid(cyclic) is False


def test_builder_derives_title_description_severity_and_timeline():
    corr_exfil = _correlation(
        "corr-d",
        AttackStage.EXFILTRATION,
        "2026-07-03T00:00:00Z",
        (("db-1", "DATABASE"), ("host-2", "HOST")),
        ("rel-d",),
        title="Database Exfiltration",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
    )
    corr_cred = _correlation(
        "corr-c",
        AttackStage.CREDENTIAL_ACCESS,
        "2026-07-03T00:01:00Z",
        (("service-1", "SERVICE"), ("db-1", "DATABASE")),
        ("rel-c",),
        title="Credential Access",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    )
    corr_exec = _correlation(
        "corr-b",
        AttackStage.EXECUTION,
        "2026-07-03T00:02:00Z",
        (("host-1", "HOST"), ("service-1", "SERVICE")),
        ("rel-b",),
        title="Execution",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
    )
    corr_initial = _correlation(
        "corr-a",
        AttackStage.INITIAL_ACCESS,
        "2026-07-03T00:03:00Z",
        (("host-1", "HOST"), ("service-a", "SERVICE")),
        ("rel-a",),
        title="Public Host Access",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
    )
    candidate = ChainCandidate(
        correlation_ids=("corr-a", "corr-b", "corr-c", "corr-d"),
        edges=(
            ChainEdge("corr-a", "corr-b", "host-1", "HOST", 2, "Shared HOST entity"),
            ChainEdge("corr-b", "corr-c", "service-1", "SERVICE", 1, "Shared SERVICE entity"),
            ChainEdge("corr-c", "corr-d", "db-1", "DATABASE", 3, "Shared DATABASE entity"),
        ),
        entities=("db-1", "host-1", "host-2", "service-1", "service-a"),
    )

    chain = AttackChainBuilder().build(
        candidate,
        (corr_exfil, corr_exec, corr_initial, corr_cred),
    )

    assert is_valid_attack_chain(chain) is True
    assert chain.title == "Public Host Access → Database Exfiltration"
    assert chain.description == (
        "Attack chain spanning 4 stages: "
        "Initial Access → Execution → Credential Access → Exfiltration"
    )
    assert chain.severity == Severity.CRITICAL
    assert chain.confidence == Confidence.MEDIUM
    assert chain.entry_point == "corr-a"
    assert chain.target == "corr-d"
    assert chain.timeline == (
        {
            "stage": "INITIAL_ACCESS",
            "timestamp": "2026-07-03T00:03:00Z",
            "correlation_id": "corr-a",
        },
        {
            "stage": "EXECUTION",
            "timestamp": "2026-07-03T00:02:00Z",
            "correlation_id": "corr-b",
        },
        {
            "stage": "CREDENTIAL_ACCESS",
            "timestamp": "2026-07-03T00:01:00Z",
            "correlation_id": "corr-c",
        },
        {
            "stage": "EXFILTRATION",
            "timestamp": "2026-07-03T00:00:00Z",
            "correlation_id": "corr-d",
        },
    )
    assert chain.relationships == ("rel-a", "rel-b", "rel-c", "rel-d")
    assert chain.supporting_findings == (
        "finding-corr-a",
        "finding-corr-b",
        "finding-corr-c",
        "finding-corr-d",
    )


def test_repository_prevents_duplicate_attack_chains():
    corr_a = _correlation(
        "corr-a",
        AttackStage.INITIAL_ACCESS,
        "2026-07-03T00:00:00Z",
        (("host-1", "HOST"),),
    )
    corr_b = _correlation(
        "corr-b",
        AttackStage.LATERAL_MOVEMENT,
        "2026-07-03T00:01:00Z",
        (("host-1", "HOST"),),
    )
    candidate = ChainDiscoveryEngine().discover(_repository(corr_a, corr_b))[0]
    chain = AttackChainBuilder().build(candidate, (corr_a, corr_b))
    repository = AttackChainRepository()

    assert repository.add(chain) is True
    assert repository.add(chain) is False
    assert len(repository) == 1


def test_repository_merges_overlapping_chains_and_preserves_evidence():
    corr_a = _correlation(
        "corr-a",
        AttackStage.INITIAL_ACCESS,
        "2026-07-03T00:00:00Z",
        (("host-1", "HOST"), ("service-1", "SERVICE")),
        ("rel-a",),
        supporting_findings=("finding-a",),
    )
    corr_b = _correlation(
        "corr-b",
        AttackStage.LATERAL_MOVEMENT,
        "2026-07-03T00:01:00Z",
        (("host-1", "HOST"), ("service-2", "SERVICE")),
        ("rel-b",),
        supporting_findings=("finding-b",),
    )
    corr_c = _correlation(
        "corr-c",
        AttackStage.COLLECTION,
        "2026-07-03T00:02:00Z",
        (("host-1", "HOST"), ("db-1", "DATABASE")),
        ("rel-b",),
        supporting_findings=("finding-c",),
        severity=Severity.CRITICAL,
    )
    first = AttackChainBuilder().build(
        ChainCandidate(
            ("corr-a", "corr-b"),
            (ChainEdge("corr-a", "corr-b", "host-1", "HOST", 2, "Shared HOST"),),
            ("host-1", "service-1", "service-2"),
        ),
        (corr_a, corr_b, corr_c),
    )
    second = AttackChainBuilder().build(
        ChainCandidate(
            ("corr-a", "corr-c"),
            (ChainEdge("corr-a", "corr-c", "host-1", "HOST", 2, "Shared HOST"),),
            ("db-1", "host-1", "service-1"),
        ),
        (corr_a, corr_b, corr_c),
    )
    repository = AttackChainRepository()

    assert repository.add(first) is True
    assert repository.add(second) is True

    merged = repository.list()
    assert len(merged) == 1
    assert merged[0].severity == Severity.CRITICAL
    assert merged[0].supporting_findings == ("finding-a", "finding-b", "finding-c")
    assert merged[0].relationships == ("rel-a", "rel-b")


def test_engine_orchestration_filters_invalid_singletons():
    corr_a = _correlation(
        "corr-a",
        AttackStage.INITIAL_ACCESS,
        "2026-07-03T00:00:00Z",
        (("host-1", "HOST"), ("service-a", "SERVICE")),
        title="Public Host Access",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
    )
    corr_b = _correlation(
        "corr-b",
        AttackStage.LATERAL_MOVEMENT,
        "2026-07-03T00:01:00Z",
        (("host-1", "HOST"), ("service-b", "SERVICE")),
        title="Privileged Host Access",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
    )
    corr_c = _correlation(
        "corr-c",
        AttackStage.IMPACT,
        "2026-07-03T00:02:00Z",
        (("host-2", "HOST"), ("service-c", "SERVICE")),
        title="Other Impact",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
    )

    chains = AttackChainEngine().run(_repository(corr_c, corr_b, corr_a))

    assert len(chains) == 1
    assert chains[0].correlations == ("corr-a", "corr-b")
    assert chains[0].severity == Severity.HIGH


def test_finalized_chain_validator_rejects_missing_evidence_and_bad_mitre():
    validator = AttackChainValidator()
    invalid = AttackStep(
        step_number=1,
        technique="Initial Access",
        mitre_id="bad",
        entity="host-1",
        evidence=(),
        description="Invalid step.",
        confidence=Confidence.HIGH,
    )

    with pytest.raises(AttackChainValidationError):
        validator.validate(
            AttackChainBuilder().build(
                ChainCandidate(
                    ("corr-a", "corr-b"),
                    (
                        ChainEdge(
                            "corr-a",
                            "corr-b",
                            "host-1",
                            "HOST",
                            2,
                            "Shared HOST",
                        ),
                    ),
                    ("host-1", "service-1"),
                ),
                (
                    _correlation(
                        "corr-a",
                        AttackStage.INITIAL_ACCESS,
                        "2026-07-03T00:00:00Z",
                        (("host-1", "HOST"),),
                    ),
                    _correlation(
                        "corr-b",
                        AttackStage.LATERAL_MOVEMENT,
                        "2026-07-03T00:01:00Z",
                        (("service-1", "SERVICE"),),
                    ),
                ),
            ).__class__(
                chain_id="bad-chain",
                entry_point="corr-a",
                target="corr-b",
                steps=(invalid,),
                participating_entities=("host-1", "service-1"),
                participating_relationships=("rel-a",),
                supporting_findings=("finding-a",),
                mitre_techniques=("bad",),
                confidence=Confidence.HIGH,
                severity=Severity.HIGH,
                description="Invalid chain.",
            )
        )


def test_engine_uses_graph_paths_and_templates_to_build_chains():
    template = AttackTemplate(
        id="tmpl-public-service",
        name="Public service to network",
        description="Template-driven graph chain.",
        mitre_chain=("T1110.001", "T1021.004"),
        required_entities=("SERVICE", "HOST", "NETWORK"),
        required_findings=(),
        entry_point_type="SERVICE",
        confidence_base=0.8,
        severity=Severity.HIGH,
        tags=(),
    )
    service = ResolvedEntity(
        id="service-1",
        entity_type=EntityType.SERVICE,
        primary_identifier="ssh",
        source_findings=["finding-corr-a"],
        attributes={"port": 22, "public": True},
    )
    host = ResolvedEntity(
        id="host-1",
        entity_type=EntityType.HOST,
        primary_identifier="10.0.0.5",
    )
    network = ResolvedEntity(
        id="network-1",
        entity_type=EntityType.NETWORK,
        primary_identifier="10.0.0.0/24",
    )
    graph = RelationshipGraph()
    graph.add_edge(
        RelationshipFact(
            id="rel-a",
            source_entity_id=service.id,
            source_entity_type=EntityType.SERVICE,
            target_entity_id=host.id,
            target_entity_type=EntityType.HOST,
            relationship_type=RelationshipType.RUNS_ON,
            source_module="test",
            source_rule="test",
            confidence=Confidence.HIGH,
            supporting_findings=("finding-corr-a",),
            confidence_contribution=0.8,
        )
    )
    graph.add_edge(
        RelationshipFact(
            id="rel-b",
            source_entity_id=host.id,
            source_entity_type=EntityType.HOST,
            target_entity_id=network.id,
            target_entity_type=EntityType.NETWORK,
            relationship_type=RelationshipType.CONNECTED_TO,
            source_module="test",
            source_rule="test",
            confidence=Confidence.HIGH,
            supporting_findings=("finding-corr-b",),
            confidence_contribution=0.8,
        )
    )
    corr_a = _correlation(
        "corr-a",
        AttackStage.INITIAL_ACCESS,
        "2026-07-03T00:00:00Z",
        (("service-1", "SERVICE"), ("host-1", "HOST")),
        ("rel-a",),
        title="Public SSH",
        mitre=("T1110.001",),
    )
    corr_b = _correlation(
        "corr-b",
        AttackStage.LATERAL_MOVEMENT,
        "2026-07-03T00:01:00Z",
        (("host-1", "HOST"), ("network-1", "NETWORK")),
        ("rel-b",),
        title="SSH Lateral Movement",
        mitre=("T1021.004",),
    )

    chains = AttackChainEngine(
        matcher=AttackPatternMatcher((template,))
    ).run(_repository(corr_a, corr_b), graph, (service, host, network))

    assert len(chains) == 1
    assert chains[0].template_id == template.id
    assert chains[0].correlations == ("corr-a", "corr-b")
    assert chains[0].entry_point == "corr-a"
    assert chains[0].mitre_techniques == ("T1021.004", "T1110.001")
    assert chains[0].confidence == Confidence.HIGH
    assert chains[0].metadata["confidence_model"] == "attack_chain_v1"
    assert chains[0].metadata["confidence_score"] == pytest.approx(0.88)


def test_template_loader_validates_json_templates(tmp_path):
    valid_path = tmp_path / "templates.json"
    valid_path.write_text(
        """
        {"templates": [{
          "id": "tmpl-json",
          "name": "JSON Template",
          "description": "Loaded from JSON.",
          "mitre_chain": ["T1110"],
          "required_entities": ["HOST"],
          "required_findings": [],
          "entry_point_type": "HOST",
          "confidence_base": 0.8,
          "severity": "HIGH",
          "tags": []
        }]}
        """,
        encoding="utf-8",
    )

    assert AttackTemplateRepository(path=valid_path).get("tmpl-json").severity is Severity.HIGH

    invalid_path = tmp_path / "bad-templates.json"
    invalid_path.write_text(
        """
        {"templates": [{
          "id": "",
          "name": "Bad",
          "description": "Invalid template.",
          "mitre_chain": [],
          "required_entities": [],
          "required_findings": [],
          "entry_point_type": "HOST",
          "confidence_base": 0.8,
          "severity": "HIGH",
          "tags": []
        }]}
        """,
        encoding="utf-8",
    )

    with pytest.raises(AttackChainSchemaError):
        AttackTemplateRepository(path=invalid_path)


def test_relationship_traversal_identifies_public_entry_points():
    service = ResolvedEntity(
        id="service-1",
        entity_type=EntityType.SERVICE,
        primary_identifier="https",
        source_findings=["finding-service"],
        attributes={"port": 443},
    )
    host = ResolvedEntity(
        id="host-1",
        entity_type=EntityType.HOST,
        primary_identifier="10.0.0.5",
    )
    graph = RelationshipGraph()
    graph.add_edge(
        RelationshipFact(
            id="rel-service-host",
            source_entity_id=service.id,
            source_entity_type=EntityType.SERVICE,
            target_entity_id=host.id,
            target_entity_type=EntityType.HOST,
            relationship_type=RelationshipType.RUNS_ON,
            source_module="test",
            source_rule="test",
            confidence=Confidence.HIGH,
            supporting_findings=("finding-service",),
        )
    )

    entry_points = RelationshipTraverser(
        graph,
        {service.id: service, host.id: host},
        (),
    ).find_entry_points()

    assert [entry.entity_id for entry in entry_points] == ["service-1"]
    assert entry_points[0].exposure_type == "EXPOSED"
    assert entry_points[0].supporting_findings == ("finding-service",)


def test_rule_registry_rules_include_attack_stages():
    stages = {rule.rule_id: rule.stage for rule in RuleRegistry().get_rules()}

    assert stages["CORR-PUBLIC-SSH-PRIVILEGED-ACCOUNT"] is AttackStage.INITIAL_ACCESS
    assert stages["CORR-ADMIN-AUTH-EXPOSED-SYSTEM"] is AttackStage.LATERAL_MOVEMENT


def test_attack_chain_foundation_contract_validation_and_repository_queries():
    template = AttackTemplate(
        id="tmpl-1",
        name="Credential abuse",
        description="Template contract.",
        mitre_chain=("T1078", "T1021.004"),
        required_entities=("HOST", "IDENTITY"),
        required_findings=("finding-a",),
        entry_point_type="HOST",
        confidence_base=0.8,
        severity=Severity.HIGH,
        tags=("identity",),
    )
    AttackChainSchema.validate_template(template)

    chain = AttackChainBuilder().build(
        ChainCandidate(
            correlation_ids=("corr-a", "corr-b"),
            edges=(ChainEdge("corr-a", "corr-b", "host-1", "HOST", 2, "Shared HOST"),),
            entities=("host-1", "identity-1"),
            rule_id=template.id,
        ),
        (
            _correlation(
                "corr-a",
                AttackStage.INITIAL_ACCESS,
                "2026-07-03T00:00:00Z",
                (("host-1", "HOST"),),
                title="Initial",
            ),
            _correlation(
                "corr-b",
                AttackStage.CREDENTIAL_ACCESS,
                "2026-07-03T00:01:00Z",
                (("identity-1", "IDENTITY"),),
                title="Credential",
            ),
        ),
    )

    AttackChainSchema.validate_chain(chain)
    repository = AttackChainRepository()

    assert repository.add(chain) is True
    assert repository.get(chain.chain_id) == chain
    assert repository.query(entity="host-1") == (chain,)
    assert repository.query(technique="T0000") == (chain,)

    invalid = AttackStep(
        step_number=1,
        technique="Initial Access",
        mitre_id="bad",
        entity="host-1",
        evidence=("finding-a",),
        description="Invalid MITRE.",
        confidence=Confidence.HIGH,
    )
    bad_chain = chain.__class__(
        chain_id="chain-bad",
        entry_point="host-1",
        steps=(invalid,),
        participating_entities=("host-1",),
        participating_relationships=("rel-a",),
        supporting_findings=("finding-a",),
        mitre_techniques=("bad",),
        confidence=Confidence.HIGH,
        severity=Severity.HIGH,
        description="Invalid chain.",
    )

    with pytest.raises(AttackChainSchemaError):
        AttackChainSchema.validate_chain(bad_chain)
    assert repository.add(bad_chain) is False
