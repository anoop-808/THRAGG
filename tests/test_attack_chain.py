from thragg.core.attack_chain_builder import AttackChainBuilder
from thragg.core.attack_chain_engine import AttackChainEngine
from thragg.core.attack_chain_repository import AttackChainRepository
from thragg.core.attack_chain_schema import is_valid_attack_chain
from thragg.core.chain_candidate import ChainCandidate
from thragg.core.chain_discovery_engine import ChainDiscoveryEngine
from thragg.core.chain_edge import AFFINITY_WEIGHTS, ChainEdge, affinity_score
from thragg.core.chain_validator import ChainValidator
from thragg.core.correlation import Correlation
from thragg.core.correlation_repository import CorrelationRepository
from thragg.core.correlation_rule import AttackStage, RuleRegistry
from thragg.core.finding import Confidence, EntityType, Severity


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
) -> Correlation:
    return Correlation(
        id=correlation_id,
        rule_id=f"rule-{correlation_id}",
        title=title or f"Correlation {correlation_id}",
        description="Test correlation.",
        severity=severity,
        confidence=confidence,
        recommendation=recommendation or f"Review {correlation_id}.",
        mitre=(),
        category="Correlation",
        tags=(),
        timestamp=timestamp,
        matched_entities=tuple(
            {"id": entity_id, "entity_type": entity_type}
            for entity_id, entity_type in entities
        ),
        matched_relationships=relationships,
        supporting_findings=(f"finding-{correlation_id}",),
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


def test_rule_registry_rules_include_attack_stages():
    stages = {rule.rule_id: rule.stage for rule in RuleRegistry().get_rules()}

    assert stages["CORR-PUBLIC-SSH-PRIVILEGED-ACCOUNT"] is AttackStage.INITIAL_ACCESS
    assert stages["CORR-ADMIN-AUTH-EXPOSED-SYSTEM"] is AttackStage.LATERAL_MOVEMENT
