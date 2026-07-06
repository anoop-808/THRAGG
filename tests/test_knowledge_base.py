from thragg.core import KnowledgeBase, RelationshipGraph
from thragg.core.foundation.core_relationship_fact import RelationshipFact, RelationshipType
from thragg.core.foundation.finding import Confidence, EntityType


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
        supporting_evidence={"port": 22},
        observed_at="2026-07-03T00:00:00Z",
    )
    defaults.update(overrides)
    return RelationshipFact(**defaults)


def test_empty_knowledge_base_returns_empty_views_and_graph():
    kb = KnowledgeBase()

    graph = kb.build_graph()

    assert len(kb) == 0
    assert kb.relationship_count == 0
    assert kb.entity_count == 0
    assert kb.get_relationships() == ()
    assert kb.get_relationships("missing") == ()
    assert kb.get_relationships_between("missing-a", "missing-b") == ()
    assert kb.has_relationship_between("missing-a", "missing-b") is False
    assert kb.get_neighbors("missing") == ()
    assert isinstance(graph, RelationshipGraph)
    assert graph.nodes() == ()
    assert graph.edges() == ()


def test_single_relationship_is_indexed_by_both_entities_and_preserves_evidence():
    kb = KnowledgeBase()
    relationship = _relationship()

    assert kb.add_relationship(relationship) is True

    assert kb.get_relationship("rel-001") is relationship
    assert kb.relationship_count == 1
    assert kb.entity_count == 2
    assert kb.get_relationships("resolved-host-1") == (relationship,)
    assert kb.get_relationships("resolved-service-1") == (relationship,)
    assert kb.get_relationships_between(
        "resolved-host-1", "resolved-service-1"
    ) == (relationship,)
    assert kb.has_relationship_between(
        "resolved-host-1", "resolved-service-1"
    ) is True
    assert kb.has_relationship_between(
        "resolved-service-1", "resolved-host-1"
    ) is False
    assert kb.get_neighbors("resolved-host-1") == ("resolved-service-1",)
    assert relationship.supporting_findings == ("finding-1",)
    assert relationship.supporting_evidence == {"port": 22}
    assert relationship.observed_at == "2026-07-03T00:00:00Z"


def test_multiple_relationships_and_large_batches_are_deterministic():
    kb = KnowledgeBase()
    relationships = [
        _relationship(
            id=f"rel-{index:03d}",
            source_entity_id=f"resolved-host-{index:03d}",
            target_entity_id=f"resolved-service-{index:03d}",
        )
        for index in range(100, 0, -1)
    ]

    accepted = kb.add_relationships(relationships)

    assert len(accepted) == 100
    assert len(kb) == 100
    assert [item.id for item in kb] == [f"rel-{index:03d}" for index in range(1, 101)]


def test_duplicate_relationships_are_rejected_without_replacing_original():
    kb = KnowledgeBase()
    original = _relationship(supporting_evidence={"port": 22})
    duplicate = _relationship(supporting_evidence={"port": 443})

    assert kb.add_relationship(original) is True
    assert kb.add_relationship(duplicate) is False

    assert len(kb) == 1
    assert kb.get_relationship("rel-001") is original
    assert kb.get_relationship("rel-001").supporting_evidence == {"port": 22}


def test_relationship_exists_and_remove_relationship_update_indexes():
    kb = KnowledgeBase()
    relationship = _relationship()
    kb.add_relationship(relationship)

    assert kb.relationship_exists("rel-001") is True
    assert kb.remove_relationship("rel-001") is True

    assert kb.relationship_exists("rel-001") is False
    assert kb.remove_relationship("rel-001") is False
    assert kb.get_relationships("resolved-host-1") == ()
    assert kb.get_relationships("resolved-service-1") == ()


def test_invalid_relationships_never_enter_knowledge_base():
    kb = KnowledgeBase()
    invalid_combo = _relationship(
        id="rel-invalid",
        source_entity_type=EntityType.USER,
        target_entity_type=EntityType.NETWORK,
        relationship_type=RelationshipType.HOSTED_IN,
    )
    malformed = _relationship(id="   ")

    assert kb.add_relationship(invalid_combo) is False
    assert kb.add_relationship(malformed) is False
    assert kb.add_relationship("not-a-relationship") is False

    assert len(kb) == 0


def test_knowledge_base_exposes_relationship_acceptance_check():
    kb = KnowledgeBase()
    valid = _relationship()
    invalid = _relationship(
        id="rel-invalid",
        source_entity_type=EntityType.USER,
        target_entity_type=EntityType.NETWORK,
        relationship_type=RelationshipType.HOSTED_IN,
    )

    assert kb.can_add_relationship(valid) is True
    assert kb.can_add_relationship(invalid) is False
    assert kb.can_add_relationship("not-a-relationship") is False


def test_build_graph_uses_stored_valid_relationships_only():
    kb = KnowledgeBase()
    valid = _relationship(id="rel-a")
    invalid = _relationship(
        id="rel-b",
        source_entity_type=EntityType.USER,
        target_entity_type=EntityType.NETWORK,
        relationship_type=RelationshipType.HOSTED_IN,
    )
    kb.add_relationship(valid)
    kb.add_relationship(invalid)

    graph = kb.build_graph()

    assert graph.nodes() == ("resolved-host-1", "resolved-service-1")
    assert graph.edges() == (valid,)
    assert graph.get_relationship("rel-a") is valid
    assert graph.get_relationship("rel-b") is None


def test_deterministic_lookup_order_for_entity_relationships():
    kb = KnowledgeBase()
    rel_b = _relationship(id="rel-b", target_entity_id="resolved-service-b")
    rel_a = _relationship(id="rel-a", target_entity_id="resolved-service-a")

    kb.add_relationship(rel_b)
    kb.add_relationship(rel_a)

    assert kb.get_relationships("resolved-host-1") == (rel_a, rel_b)
    assert kb.get_neighbors("resolved-host-1") == (
        "resolved-service-a",
        "resolved-service-b",
    )
