"""
core.attack_chain_engine
========================

Milestone 6 orchestration layer.
"""

from __future__ import annotations

from .attack_chain import AttackChain
from .attack_chain_builder import AttackChainBuilder
from .attack_chain_repository import AttackChainRepository
from .chain_discovery_engine import ChainDiscoveryEngine
from .chain_validator import ChainValidator
from ..correlation.correlation_repository import CorrelationRepository

__all__ = ["AttackChainEngine"]


class AttackChainEngine:
    """Discover, validate, build, and store attack chains."""

    def __init__(
        self,
        discovery: ChainDiscoveryEngine | None = None,
        validator: ChainValidator | None = None,
        builder: AttackChainBuilder | None = None,
        repository: AttackChainRepository | None = None,
    ) -> None:
        self.discovery = discovery or ChainDiscoveryEngine()
        self.validator = validator or ChainValidator()
        self.builder = builder or AttackChainBuilder()
        self.repository = repository or AttackChainRepository()

    def run(self, correlations: CorrelationRepository) -> tuple[AttackChain, ...]:
        """Build attack chains from a CorrelationRepository."""
        correlation_items = correlations.list()
        for candidate in self.discovery.discover(correlations):
            if self.validator.is_valid(candidate):
                self.repository.add(self.builder.build(candidate, correlation_items))
        return self.repository.list()
