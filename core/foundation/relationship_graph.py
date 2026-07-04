"""
core.relationship_graph
=======================

Lightweight traversal graph generated from the KnowledgeBase.

The graph is not the source of truth.  It stores node ids and references to
validated RelationshipFact objects only.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import TYPE_CHECKING

import networkx as nx

from .core_relationship_fact import RelationshipFact
from .core_relationship_validator import RelationshipValidator

__all__ = ["RelationshipGraph"]

if TYPE_CHECKING:
    from .knowledge_base import KnowledgeBase


class RelationshipGraph:
    """Directed graph of resolved entity ids and relationship fact references.

    Example:
        graph = RelationshipGraph.from_knowledge_base(kb)
        graph.neighbors("resolved-host-1")
    """

    def __init__(self) -> None:
        self._graph = nx.MultiDiGraph()
        self._edges: dict[str, RelationshipFact] = {}

    # Public API

    @property
    def entity_count(self) -> int:
        """Number of node ids in the graph."""
        return self._graph.number_of_nodes()

    @property
    def relationship_count(self) -> int:
        """Number of relationship edges referenced by the graph."""
        return len(self._edges)

    @property
    def edge_count(self) -> int:
        """Alias for relationship_count."""
        return self.relationship_count

    def add_node(self, entity_id: object) -> bool:
        """Add an entity id node, returning False for invalid or duplicate ids."""
        if not isinstance(entity_id, str) or not entity_id.strip():
            return False
        if self._graph.has_node(entity_id):
            return False
        self._graph.add_node(entity_id)
        return True

    def add_edge(self, relationship: object) -> bool:
        """Add a relationship edge, returning False for invalid or duplicate input."""
        if not isinstance(relationship, RelationshipFact):
            return False
        if relationship.id in self._edges:
            return False
        if not RelationshipValidator.is_valid(relationship):
            return False

        self.add_node(relationship.source_entity_id)
        self.add_node(relationship.target_entity_id)
        self._edges[relationship.id] = relationship
        self._graph.add_edge(
            relationship.source_entity_id,
            relationship.target_entity_id,
            key=relationship.id,
            relationship=relationship,
            relationship_type=relationship.relationship_type,
            source_module=relationship.source_module,
            supporting_findings=relationship.supporting_findings,
            confidence_contribution=relationship.confidence_contribution,
        )
        return True

    def nodes(self) -> tuple[str, ...]:
        """Return node ids in deterministic order."""
        # Deterministic guarantee: node iteration is sorted by entity id.
        return tuple(sorted(self._graph.nodes))

    def edges(self) -> tuple[RelationshipFact, ...]:
        """Return edges in deterministic relationship id order."""
        # Deterministic guarantee: edge iteration is sorted by relationship id.
        return tuple(self._edges[item_id] for item_id in sorted(self._edges))

    def neighbors(self, entity_id: str) -> tuple[str, ...]:
        """Return outbound neighbor ids for an entity."""
        return tuple(
            sorted(
                target
                for _, target in self._graph.out_edges(entity_id)
            )
        )

    def get_relationships_between(
        self, source_entity_id: str, target_entity_id: str
    ) -> tuple[RelationshipFact, ...]:
        """Return directed relationship edges from source to target.

        Example:
            graph.get_relationships_between("resolved-host-1", "resolved-service-1")
        """
        return tuple(
            relationship
            for relationship in self.outgoing_edges(source_entity_id)
            if relationship.target_entity_id == target_entity_id
        )

    def incoming_edges(self, entity_id: str) -> tuple[RelationshipFact, ...]:
        """Return incoming edges for an entity in deterministic order."""
        return self._edge_tuple(
            {
                key
                for _, _, key in self._graph.in_edges(entity_id, keys=True)
            }
        )

    def outgoing_edges(self, entity_id: str) -> tuple[RelationshipFact, ...]:
        """Return outgoing edges for an entity in deterministic order."""
        return self._edge_tuple(
            {
                key
                for _, _, key in self._graph.out_edges(entity_id, keys=True)
            }
        )

    def shortest_path(
        self, source_entity_id: str, target_entity_id: str
    ) -> tuple[str, ...]:
        """Return the shortest directed node path, or empty tuple when absent."""
        try:
            return tuple(
                nx.shortest_path(self._graph, source_entity_id, target_entity_id)
            )
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return ()

    def connected_components(self) -> tuple[tuple[str, ...], ...]:
        """Return weakly connected components in deterministic order."""
        components = [
            tuple(sorted(component))
            for component in nx.weakly_connected_components(self._graph)
        ]
        return tuple(sorted(components, key=lambda item: (len(item), item)))

    def get_relationship(self, relationship_id: str) -> RelationshipFact | None:
        """Return one relationship edge by id, or None when absent."""
        return self._edges.get(relationship_id)

    def merge_entity(self, duplicate_entity_id: str, canonical_entity_id: str) -> bool:
        """Merge a duplicate graph node into a canonical node."""
        if (
            duplicate_entity_id == canonical_entity_id
            or not self._graph.has_node(duplicate_entity_id)
        ):
            return False
        self.add_node(canonical_entity_id)
        nx.contracted_nodes(
            self._graph,
            canonical_entity_id,
            duplicate_entity_id,
            self_loops=False,
            copy=False,
        )
        return True

    def add_entity(self, entity_id: object) -> bool:
        """Alias for add_node."""
        return self.add_node(entity_id)

    def add_relationship(self, relationship: object) -> bool:
        """Alias for add_edge."""
        return self.add_edge(relationship)

    def relationship_exists(self, relationship_id: str) -> bool:
        """Return True when an edge id is present."""
        return relationship_id in self._edges

    def has_relationship_between(
        self, source_entity_id: str, target_entity_id: str
    ) -> bool:
        """Return True when any directed edge exists between two entity ids."""
        return bool(
            self.get_relationships_between(source_entity_id, target_entity_id)
        )

    @classmethod
    def from_knowledge_base(cls, knowledge_base: KnowledgeBase) -> "RelationshipGraph":
        """Build a graph from all relationships stored in a KnowledgeBase.

        Ownership: RelationshipGraph never owns relationship data; it references
        the KnowledgeBase facts and exists only for traversal.
        """
        graph = cls()
        for relationship in knowledge_base.get_relationships():
            graph.add_edge(relationship)
        return graph

    def __iter__(self) -> Iterator[RelationshipFact]:
        """Iterate edges in deterministic relationship id order."""
        return iter(self.edges())

    def __len__(self) -> int:
        """Return the number of graph edges."""
        return len(self._edges)

    # Internal helpers

    def _edge_tuple(self, relationship_ids: set[str]) -> tuple[RelationshipFact, ...]:
        return tuple(self._edges[item_id] for item_id in sorted(relationship_ids))
