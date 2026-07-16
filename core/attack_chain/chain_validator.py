"""
core.chain_validator
====================

Validation for ChainCandidate objects.
"""

from __future__ import annotations

from .chain_candidate import ChainCandidate

__all__ = ["ChainValidator"]


class ChainValidator:
    """Validate chain candidates without building AttackChain objects."""

    def __init__(
        self,
        min_correlations: int = 2,
        min_affinity_score: int = 1,
        min_entity_diversity: int = 2,
    ) -> None:
        self.min_correlations = min_correlations
        self.min_affinity_score = min_affinity_score
        self.min_entity_diversity = min_entity_diversity

    def is_valid(self, candidate: ChainCandidate) -> bool:
        """Return True when a candidate satisfies Milestone 6 rules."""
        from .attack_template_repository import AttackTemplateRepository
        repo = AttackTemplateRepository()
        template = repo.get(candidate.rule_id)

        min_corr = getattr(template, "min_correlations", self.min_correlations) if template else self.min_correlations
        min_entities = 1 if template and template.id == "TMPL-IDENTITY-COMPROMISE" else self.min_entity_diversity
        min_affinity = 0 if template and template.id == "TMPL-IDENTITY-COMPROMISE" else self.min_affinity_score

        if len(candidate.correlation_ids) < min_corr:
            return False
        if len(candidate.entities) < min_entities:
            return False
        if sum(edge.affinity_score for edge in candidate.edges) < min_affinity:
            return False
        return not self._has_cycle(candidate)

    def _has_cycle(self, candidate: ChainCandidate) -> bool:
        visiting: set[str] = set()
        visited: set[str] = set()
        graph = {correlation_id: set() for correlation_id in candidate.correlation_ids}
        for edge in candidate.edges:
            graph.setdefault(edge.from_correlation_id, set()).add(edge.to_correlation_id)

        def visit(correlation_id: str) -> bool:
            if correlation_id in visiting:
                return True
            if correlation_id in visited:
                return False
            visiting.add(correlation_id)
            for neighbor in sorted(graph.get(correlation_id, set())):
                if visit(neighbor):
                    return True
            visiting.remove(correlation_id)
            visited.add(correlation_id)
            return False

        return any(visit(correlation_id) for correlation_id in sorted(graph))
