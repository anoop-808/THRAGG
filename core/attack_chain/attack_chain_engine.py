"""
core.attack_chain_engine
========================

Milestone 6 orchestration layer.
"""

from __future__ import annotations

import logging

from .attack_chain import AttackChain
from .attack_chain_builder import AttackChainBuilder
from .attack_chain_repository import AttackChainRepository
from .attack_chain_validator import AttackChainValidator
from .attack_pattern_matcher import AttackPatternMatcher
from .chain_discovery_engine import ChainDiscoveryEngine
from .chain_validator import ChainValidator
from ..correlation.correlation_repository import CorrelationRepository
from ..foundation.relationship_graph import RelationshipGraph
from ..foundation.resolved_entity import ResolvedEntity

__all__ = ["AttackChainEngine"]

LOGGER = logging.getLogger(__name__)


class AttackChainEngine:
    """Discover, validate, build, and store attack chains."""

    def __init__(
        self,
        discovery: ChainDiscoveryEngine | None = None,
        validator: ChainValidator | None = None,
        chain_validator: AttackChainValidator | None = None,
        matcher: AttackPatternMatcher | None = None,
        builder: AttackChainBuilder | None = None,
        repository: AttackChainRepository | None = None,
    ) -> None:
        self.discovery = discovery or ChainDiscoveryEngine()
        self.validator = validator or ChainValidator()
        self.chain_validator = chain_validator or AttackChainValidator()
        self.matcher = matcher or AttackPatternMatcher()
        self.builder = builder or AttackChainBuilder()
        self.repository = repository or AttackChainRepository()

    def run(
        self,
        correlations: CorrelationRepository,
        graph: RelationshipGraph | None = None,
        entities: dict[str, ResolvedEntity] | tuple[ResolvedEntity, ...] | None = None,
    ) -> tuple[AttackChain, ...]:
        """Build attack chains from correlations, optionally constrained by a graph."""
        correlation_items = correlations.list()
        if graph is not None and entities is not None:
            entity_map = (
                entities
                if isinstance(entities, dict)
                else {entity.id: entity for entity in entities}
            )
            for result in self.matcher.match_graph_paths(graph, entity_map, correlation_items):
                print(f"Result: match={result.is_match()} entry={result.entry_point_match} mitre={result.mitre_sequence_match} entity={result.entity_coverage} finding={result.finding_coverage}")
                if result.is_match() and self.validator.is_valid(result.candidate):
                    chain = self.builder.build(
                        result.candidate,
                        correlation_items,
                        template_match_score=result.overall_score,
                    )
                    if self.chain_validator.is_valid(chain):
                        self.repository.add(chain)
                    else:
                        LOGGER.debug("Rejected invalid attack chain %s", chain.chain_id)
            return self.repository.list()

        for candidate in self.discovery.discover(correlations):
            if self.validator.is_valid(candidate):
                chain = self.builder.build(candidate, correlation_items)
                if self.chain_validator.is_valid(chain):
                    self.repository.add(chain)
                else:
                    LOGGER.debug("Rejected invalid attack chain %s", chain.chain_id)
        return self.repository.list()
