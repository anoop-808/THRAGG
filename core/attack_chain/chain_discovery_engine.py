"""
core.chain_discovery_engine
===========================

Deterministic DFS discovery of connected Correlation components.
"""

from __future__ import annotations

from .attack_chain_rule import AttackChainRule, AttackChainRuleRepository
from .chain_candidate import ChainCandidate
from .chain_edge import ChainEdge, affinity_score
from ..correlation.correlation import Correlation
from ..correlation.correlation_repository import CorrelationRepository
from ..correlation.correlation_rule import AttackStage

__all__ = ["ChainDiscoveryEngine", "stage_sort_key"]


STAGE_ORDER = {stage.value: index for index, stage in enumerate(AttackStage)}


class ChainDiscoveryEngine:
    """Discover connected correlations. No validation or filtering."""

    def __init__(self, rules: tuple[AttackChainRule, ...] | None = None) -> None:
        self.rules = rules or AttackChainRuleRepository().list()

    def discover(
        self,
        repository: CorrelationRepository,
    ) -> tuple[ChainCandidate, ...]:
        """Return connected components from repository correlations."""
        correlations = {correlation.id: correlation for correlation in repository.list()}
        if not correlations:
            return ()

        edges = self._edges(tuple(correlations[item_id] for item_id in sorted(correlations)))
        adjacency = self._adjacency(correlations, edges)
        candidates: list[ChainCandidate] = []
        seen: set[str] = set()

        for correlation_id in sorted(correlations):
            if correlation_id in seen:
                continue
            component = self._dfs(correlation_id, adjacency)
            seen.update(component)
            component_edges = tuple(
                edge
                for edge in edges
                if edge.from_correlation_id in component
                and edge.to_correlation_id in component
            )
            component_correlations = tuple(
                correlations[item_id] for item_id in sorted(component)
            )
            candidates.append(
                ChainCandidate(
                    correlation_ids=tuple(sorted(component)),
                    edges=component_edges,
                    entities=self._candidate_entities(correlations, component),
                    rule_id=self._rule_id(component_correlations),
                )
            )
        return tuple(candidates)

    def _edges(self, correlations: tuple[Correlation, ...]) -> tuple[ChainEdge, ...]:
        edges: list[ChainEdge] = []
        for index, left in enumerate(correlations):
            for right in correlations[index + 1:]:
                for entity_id, entity_type in self._shared_entities(left, right):
                    first, second = sorted((left, right), key=stage_sort_key)
                    edges.append(
                        ChainEdge(
                            from_correlation_id=first.id,
                            to_correlation_id=second.id,
                            shared_entity_id=entity_id,
                            shared_entity_type=entity_type,
                            affinity_score=affinity_score(entity_type),
                            reason=f"Shared {entity_type} entity",
                        )
                    )
        return tuple(
            sorted(
                edges,
                key=lambda edge: (
                    edge.from_correlation_id,
                    edge.to_correlation_id,
                    edge.shared_entity_id,
                ),
            )
        )

    def _shared_entities(
        self,
        left: Correlation,
        right: Correlation,
    ) -> tuple[tuple[str, str], ...]:
        left_entities = _entity_map(left)
        right_entities = _entity_map(right)
        return tuple(
            (entity_id, left_entities[entity_id])
            for entity_id in sorted(left_entities.keys() & right_entities.keys())
        )

    def _adjacency(
        self,
        correlations: dict[str, Correlation],
        edges: tuple[ChainEdge, ...],
    ) -> dict[str, set[str]]:
        adjacency = {correlation_id: set() for correlation_id in correlations}
        for edge in edges:
            adjacency[edge.from_correlation_id].add(edge.to_correlation_id)
            adjacency[edge.to_correlation_id].add(edge.from_correlation_id)
        return adjacency

    def _dfs(self, start: str, adjacency: dict[str, set[str]]) -> set[str]:
        seen: set[str] = set()
        stack = [start]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(
                neighbor
                for neighbor in sorted(adjacency[current], reverse=True)
                if neighbor not in seen
            )
        return seen

    def _candidate_entities(
        self,
        correlations: dict[str, Correlation],
        component: set[str],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    str(entity["id"])
                    for correlation_id in component
                    for entity in correlations[correlation_id].matched_entities
                    if "id" in entity
                }
            )
        )

    def _rule_id(self, correlations: tuple[Correlation, ...]) -> str:
        specific_rules = tuple(
            sorted(
                self.rules,
                key=lambda rule: (not rule.stage_sequence, rule.rule_id),
            )
        )
        return next(
            (rule.rule_id for rule in specific_rules if rule.matches(correlations)),
            "ATTACK-CHAIN-GENERIC",
        )


def stage_sort_key(correlation: Correlation) -> tuple[int, str, str]:
    """Sort by stage, then timestamp, then id."""
    stage = str(correlation.correlation_explanation.get("stage", "DISCOVERY"))
    return (STAGE_ORDER.get(stage, len(STAGE_ORDER)), correlation.timestamp, correlation.id)


def _entity_map(correlation: Correlation) -> dict[str, str]:
    return {
        str(entity["id"]): str(entity.get("type", "UNKNOWN"))
        for entity in correlation.matched_entities
        if "id" in entity
    }
