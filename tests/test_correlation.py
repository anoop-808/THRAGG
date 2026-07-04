from thragg.core.correlation.correlation import Correlation
from thragg.core.correlation.correlation_engine import CorrelationEngine
from thragg.core.correlation.correlation_repository import CorrelationRepository
from thragg.core.correlation.correlation_rule import CorrelationRule, RelationshipPattern, RuleRegistry
from thragg.core.correlation.correlation_schema import is_valid_correlation
from thragg.core.correlation.correlation_builder import CorrelationBuilder
from thragg.core.correlation.pattern_evaluator import PatternEvaluator
from thragg.core.foundation.core_relationship_fact import RelationshipFact, RelationshipType
from thragg.core.foundation.finding import Confidence, EntityType, Severity
from thragg.core.foundation.knowledge_base import KnowledgeBase
from thragg.core.foundation.resolved_entity import ResolvedEntity


def _relationship(**overrides) -> RelationshipFact:
    defaults = dict(
        id="rel-001",
        source_entity_id="resolved-host-1",
        source_entity_type=EntityType.HOST,
        target_entity_id="resolved-service-1",
        target_entity_type=EntityType.SERVICE,
        relationship_type=RelationshipType.EXPOSES,
        source_module="nmap",
        source_rule="NMAP-EXPOSED-SERVICE",
        confidence=Confidence.HIGH,
        supporting_findings=("finding-1",),
        supporting_evidence={"port": 22, "public": True},
        observed_at="2026-07-03T00:00:00Z",
    )
    defaults.update(overrides)
    return RelationshipFact(**defaults)


def _entity(entity_id: str, entity_type: EntityType, **attributes) -> ResolvedEntity:
    return ResolvedEntity(
        id=entity_id,
        entity_type=entity_type,
        primary_identifier=entity_id,
        attributes=attributes,
    )


def test_rule_creation_and_correlation_schema():
    rule = CorrelationRule(
        rule_id="CORR-001",
        title="Public SSH host",
        description="A host exposes SSH.",
        version="1.0",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        mitre=("T1021.004",),
        category="Network Exposure",
        tags=("ssh",),
        recommendation="Restrict SSH exposure.",
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
    correlation = Correlation(
        id="corr-001",
        rule_id=rule.rule_id,
        title=rule.title,
        description=rule.description,
        severity=rule.severity,
        confidence=rule.confidence,
        recommendation=rule.recommendation,
        mitre=rule.mitre,
        category=rule.category,
        tags=rule.tags,
        timestamp="2026-07-03T00:00:00Z",
        matched_entities=({"variable": "HOST", "id": "resolved-host-1"},),
        matched_relationships=("rel-001",),
        supporting_findings=("finding-1",),
        correlation_explanation={"triggered_rule": rule.rule_id},
    )

    assert rule.patterns[0].source_variable == "HOST"
    assert is_valid_correlation(correlation) is True


def test_pattern_matching_and_variable_binding():
    kb = KnowledgeBase()
    exposed = _relationship(id="rel-a")
    auth = _relationship(
        id="rel-b",
        source_entity_id="resolved-user-1",
        source_entity_type=EntityType.USER,
        target_entity_id="resolved-host-1",
        target_entity_type=EntityType.HOST,
        relationship_type=RelationshipType.AUTHENTICATED_TO,
        supporting_findings=("finding-2",),
    )
    kb.add_relationships((auth, exposed))
    rule = CorrelationRule(
        rule_id="CORR-SSH-AUTH",
        title="Authenticated exposed host",
        description="A user authenticated to a host exposing SSH.",
        version="1.0",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        mitre=(),
        category="Correlation",
        tags=(),
        recommendation="Review access.",
        patterns=(
            RelationshipPattern(
                "HOST",
                EntityType.HOST,
                RelationshipType.EXPOSES,
                "SERVICE",
                EntityType.SERVICE,
            ),
            RelationshipPattern(
                "USER",
                EntityType.USER,
                RelationshipType.AUTHENTICATED_TO,
                "HOST",
                EntityType.HOST,
            ),
        ),
    )

    matches = PatternEvaluator().evaluate(rule, kb)

    assert len(matches) == 1
    assert matches[0].bindings["HOST"].id == "resolved-host-1"
    assert [relationship.id for relationship in matches[0].relationships] == [
        "rel-a",
        "rel-b",
    ]


def test_type_aware_binding_rejects_inconsistent_entity_index():
    kb = KnowledgeBase()
    kb.add_relationship(_relationship())
    rule = CorrelationRule(
        rule_id="CORR-BAD-ENTITY",
        title="Bad entity",
        description="Entity type mismatch.",
        version="1.0",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        mitre=(),
        category="Correlation",
        tags=(),
        recommendation="Fix data.",
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

    matches = PatternEvaluator().evaluate(
        rule,
        kb,
        {"resolved-host-1": _entity("resolved-host-1", EntityType.USER)},
    )

    assert matches == ()


def test_condition_evaluation_rejects_failed_bindings():
    from thragg.core.correlation.correlation_rule import EntityAttributeEqualsCondition

    kb = KnowledgeBase()
    kb.add_relationship(_relationship())
    rule = CorrelationRule(
        rule_id="CORR-PRIVILEGED",
        title="Privileged host",
        description="Requires privileged entity.",
        version="1.0",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        mitre=(),
        category="Correlation",
        tags=(),
        recommendation="Review.",
        patterns=(
            RelationshipPattern(
                "HOST",
                EntityType.HOST,
                RelationshipType.EXPOSES,
                "SERVICE",
                EntityType.SERVICE,
            ),
        ),
        conditions=(
            EntityAttributeEqualsCondition("HOST", "public", True),
        ),
    )

    assert PatternEvaluator().evaluate(rule, kb) == ()
    assert len(
        PatternEvaluator().evaluate(
            rule,
            kb,
            {"resolved-host-1": _entity("resolved-host-1", EntityType.HOST, public=True)},
        )
    ) == 1


def test_empty_knowledge_base_and_malformed_rules_return_no_matches():
    kb = KnowledgeBase()
    rule = CorrelationRule(
        rule_id="CORR-EMPTY",
        title="Empty",
        description="No patterns.",
        version="1.0",
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        mitre=(),
        category="Correlation",
        tags=(),
        recommendation="None.",
        patterns=(),
    )

    assert PatternEvaluator().evaluate(rule, kb) == ()


def test_builder_constructs_correlation_and_explanation():
    kb = KnowledgeBase()
    kb.add_relationship(_relationship())
    rule = CorrelationRule(
        rule_id="CORR-BUILD",
        title="Build correlation",
        description="Builds from a match.",
        version="1.0",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        mitre=("T0000",),
        category="Correlation",
        tags=("test",),
        recommendation="Review.",
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
    match = PatternEvaluator().evaluate(rule, kb)[0]

    correlation = CorrelationBuilder().build(rule, match)

    assert is_valid_correlation(correlation) is True
    assert correlation.rule_id == "CORR-BUILD"
    assert correlation.matched_relationships == ("rel-001",)
    assert correlation.supporting_findings == ("finding-1",)
    assert correlation.correlation_explanation["triggered_rule"] == "CORR-BUILD"
    assert correlation.correlation_explanation["supporting_evidence"] == [
        {"port": 22, "public": True}
    ]


def test_rule_registry_is_deterministic():
    registry = RuleRegistry()
    rule_ids = [rule.rule_id for rule in registry.get_rules()]

    assert rule_ids == sorted(rule_ids)
    assert registry.get_rule("CORR-ADMIN-AUTH-EXPOSED-SYSTEM") is not None
    assert registry.get_rule("missing") is None


def test_repository_prevents_duplicates():
    kb = KnowledgeBase()
    kb.add_relationship(_relationship())
    rule = RuleRegistry().get_rule("CORR-ADMIN-AUTH-EXPOSED-SYSTEM")
    assert rule is not None
    match_rule = CorrelationRule(
        rule_id=rule.rule_id,
        title=rule.title,
        description=rule.description,
        version=rule.version,
        severity=rule.severity,
        confidence=rule.confidence,
        mitre=rule.mitre,
        category=rule.category,
        tags=rule.tags,
        recommendation=rule.recommendation,
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
    correlation = CorrelationBuilder().build(
        match_rule,
        PatternEvaluator().evaluate(match_rule, kb)[0],
    )
    repository = CorrelationRepository()

    assert repository.add(correlation) is True
    assert repository.add(correlation) is False
    assert len(repository) == 1


def test_engine_orchestration_generates_builtin_correlation():
    kb = KnowledgeBase()
    kb.add_relationship(_relationship(id="rel-exposes"))
    kb.add_relationship(
        _relationship(
            id="rel-auth",
            source_entity_id="resolved-user-1",
            source_entity_type=EntityType.USER,
            target_entity_id="resolved-host-1",
            target_entity_type=EntityType.HOST,
            relationship_type=RelationshipType.AUTHENTICATED_TO,
            supporting_findings=("finding-auth",),
        )
    )
    entities = {
        "resolved-host-1": _entity("resolved-host-1", EntityType.HOST, public=True),
        "resolved-user-1": _entity(
            "resolved-user-1",
            EntityType.USER,
            admin=True,
            privileged=True,
        ),
        "resolved-service-1": _entity("resolved-service-1", EntityType.SERVICE),
    }
    engine = CorrelationEngine(RuleRegistry().get_rules())

    correlations = engine.run(kb, entities)

    assert [correlation.rule_id for correlation in correlations] == [
        "CORR-ADMIN-AUTH-EXPOSED-SYSTEM",
        "CORR-PUBLIC-SSH-PRIVILEGED-ACCOUNT",
    ]


def test_malformed_relationships_do_not_enter_correlation_flow():
    kb = KnowledgeBase()
    malformed = _relationship(
        id="rel-bad",
        source_entity_type=EntityType.USER,
        target_entity_type=EntityType.NETWORK,
        relationship_type=RelationshipType.HOSTED_IN,
    )

    assert kb.add_relationship(malformed) is False
    assert CorrelationEngine(RuleRegistry().get_rules()).run(kb) == ()
