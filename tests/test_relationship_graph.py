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


def test_empty_graph_has_empty_deterministic_views():
    graph = RelationshipGraph()

    assert len(graph) == 0
    assert graph.relationship_count == 0
    assert graph.edge_count == 0
    assert graph.entity_count == 0
    assert graph.nodes() == ()
    assert graph.edges() == ()
    assert graph.neighbors("missing") == ()
    assert graph.get_relationships_between("missing-a", "missing-b") == ()
    assert graph.has_relationship_between("missing-a", "missing-b") is False
    assert graph.incoming_edges("missing") == ()
    assert graph.outgoing_edges("missing") == ()


def test_add_node_rejects_invalid_and_duplicate_nodes():
    graph = RelationshipGraph()

    assert graph.add_node("resolved-host-1") is True
    assert graph.add_node("resolved-host-1") is False
    assert graph.add_node("   ") is False
    assert graph.add_node(None) is False

    assert graph.nodes() == ("resolved-host-1",)


def test_single_edge_adds_nodes_and_supports_lookup():
    graph = RelationshipGraph()
    relationship = _relationship()

    assert graph.add_edge(relationship) is True

    assert graph.nodes() == ("resolved-host-1", "resolved-service-1")
    assert graph.edges() == (relationship,)
    assert graph.relationship_count == 1
    assert graph.edge_count == 1
    assert graph.entity_count == 2
    assert graph.relationship_exists("rel-001") is True
    assert graph.get_relationship("rel-001") is relationship
    assert graph.get_relationships_between(
        "resolved-host-1", "resolved-service-1"
    ) == (relationship,)
    assert graph.has_relationship_between(
        "resolved-host-1", "resolved-service-1"
    ) is True
    assert graph.has_relationship_between(
        "resolved-service-1", "resolved-host-1"
    ) is False
    assert graph.neighbors("resolved-host-1") == ("resolved-service-1",)


def test_duplicate_and_malformed_edges_are_rejected():
    graph = RelationshipGraph()
    relationship = _relationship()
    invalid = _relationship(
        id="rel-invalid",
        source_entity_type=EntityType.USER,
        target_entity_type=EntityType.NETWORK,
        relationship_type=RelationshipType.HOSTED_IN,
    )

    assert graph.add_edge(relationship) is True
    assert graph.add_edge(relationship) is False
    assert graph.add_edge(invalid) is False
    assert graph.add_edge("not-a-relationship") is False

    assert len(graph) == 1


def test_incoming_and_outgoing_edges_are_deterministic():
    graph = RelationshipGraph()
    rel_b = _relationship(id="rel-b", target_entity_id="resolved-service-b")
    rel_a = _relationship(id="rel-a", target_entity_id="resolved-service-a")
    rel_in = _relationship(
        id="rel-in",
        source_entity_id="resolved-service-c",
        source_entity_type=EntityType.SERVICE,
        target_entity_id="resolved-host-1",
        target_entity_type=EntityType.HOST,
        relationship_type=RelationshipType.CONNECTED_TO,
    )

    graph.add_edge(rel_b)
    graph.add_edge(rel_a)
    graph.add_edge(rel_in)

    assert graph.outgoing_edges("resolved-host-1") == (rel_a, rel_b)
    assert graph.incoming_edges("resolved-host-1") == (rel_in,)
    assert graph.neighbors("resolved-host-1") == (
        "resolved-service-a",
        "resolved-service-b",
    )


def test_graph_generation_from_knowledge_base():
    kb = KnowledgeBase()
    rel_a = _relationship(id="rel-a")
    rel_b = _relationship(
        id="rel-b",
        source_entity_id="resolved-host-2",
        target_entity_id="resolved-service-2",
    )
    kb.add_relationship(rel_b)
    kb.add_relationship(rel_a)

    graph = RelationshipGraph.from_knowledge_base(kb)

    assert graph.nodes() == (
        "resolved-host-1",
        "resolved-host-2",
        "resolved-service-1",
        "resolved-service-2",
    )
    assert graph.edges() == (rel_a, rel_b)


def test_large_batch_edges_keep_deterministic_iteration():
    graph = RelationshipGraph()
    relationships = [
        _relationship(
            id=f"rel-{index:03d}",
            source_entity_id=f"resolved-host-{index:03d}",
            target_entity_id=f"resolved-service-{index:03d}",
        )
        for index in range(100, 0, -1)
    ]

    for relationship in relationships:
        assert graph.add_edge(relationship) is True

    assert len(graph) == 100
    assert [item.id for item in graph] == [
        f"rel-{index:03d}" for index in range(1, 101)
    ]


def test_relationship_fact_reference_and_evidence_are_not_mutated():
    graph = RelationshipGraph()
    relationship = _relationship(supporting_evidence={"port": 22})
    before = relationship.to_dict()

    graph.add_edge(relationship)

    assert graph.get_relationship("rel-001") is relationship
    assert relationship.to_dict() == before
