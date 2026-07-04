"""
core.correlation_engine
=======================

Milestone 5 orchestration layer.
"""

from __future__ import annotations

from .correlation import Correlation
from .correlation_builder import CorrelationBuilder
from .correlation_repository import CorrelationRepository
from .correlation_rule import CorrelationRule
from .knowledge_base import KnowledgeBase
from .pattern_evaluator import PatternEvaluator
from .resolved_entity import ResolvedEntity

__all__ = ["CorrelationEngine"]


class CorrelationEngine:
    """Evaluate registered rules and store non-duplicate correlations."""

    def __init__(
        self,
        rules: tuple[CorrelationRule, ...],
        evaluator: PatternEvaluator | None = None,
        builder: CorrelationBuilder | None = None,
        repository: CorrelationRepository | None = None,
    ) -> None:
        self.rules = rules
        self.evaluator = evaluator or PatternEvaluator()
        self.builder = builder or CorrelationBuilder()
        self.repository = repository or CorrelationRepository()

    def run(
        self,
        knowledge_base: KnowledgeBase,
        resolved_entities: dict[str, ResolvedEntity] | None = None,
    ) -> tuple[Correlation, ...]:
        """Evaluate all rules and return stored correlations."""
        for rule in self.rules:
            for match in self.evaluator.evaluate(rule, knowledge_base, resolved_entities):
                self.repository.add(self.builder.build(rule, match))
        return self.repository.list()
