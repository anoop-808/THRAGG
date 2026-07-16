"""
core.attack_pattern_matcher
============================

Match graph paths against attack templates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .attack_template import AttackTemplate
from .chain_edge import ChainEdge, affinity_score
from ..foundation.relationship_graph import RelationshipGraph
from ..foundation.resolved_entity import ResolvedEntity
from ..correlation.correlation import Correlation

if TYPE_CHECKING:
    from .chain_discovery_engine import ChainCandidate
    from .relationship_traverser import AttackPath

__all__ = ["AttackPatternMatcher", "TemplateMatchResult"]


@dataclass(frozen=True)
class TemplateMatchResult:
    """Result of matching a chain candidate against an attack template."""

    template: AttackTemplate
    candidate: "ChainCandidate"
    mitre_sequence_match: float  # 0.0 - 1.0
    entity_coverage: float       # 0.0 - 1.0
    finding_coverage: float      # 0.0 - 1.0
    entry_point_match: bool
    overall_score: float         # 0.0 - 1.0

    def is_match(self, threshold: float = 0.5) -> bool:
        """Return True if the match score meets the threshold."""
        return self.overall_score >= threshold


class AttackPatternMatcher:
    """Match chain candidates against attack templates."""

    def __init__(
        self,
        templates: tuple[AttackTemplate, ...] | None = None,
    ) -> None:
        if templates is not None:
            self._templates = templates
        else:
            from .attack_template_repository import AttackTemplateRepository
            self._templates = AttackTemplateRepository().list()

    def match_candidate(
        self,
        candidate: "ChainCandidate",
        correlations: tuple[Correlation, ...],
    ) -> tuple[TemplateMatchResult, ...]:
        """Match a candidate against all templates, return scored results."""
        results = []
        for template in self._templates:
            result = self._score_candidate(template, candidate, correlations)
            if result.overall_score > 0:
                results.append(result)
        return tuple(sorted(results, key=lambda r: r.overall_score, reverse=True))

    def match_graph_paths(
        self,
        graph: RelationshipGraph,
        entities: dict[str, ResolvedEntity],
        correlations: tuple[Correlation, ...] = (),
    ) -> tuple[TemplateMatchResult, ...]:
        """
        Find attack paths in the relationship graph matching templates.

        This is the primary entry point for template-driven detection.
        """
        from .relationship_traverser import RelationshipTraverser

        traverser = RelationshipTraverser(graph, entities, self._templates)
        results: list[TemplateMatchResult] = []
        paths = list(traverser.find_attack_paths())
        print(f"Traverser returned {len(paths)} paths.")
        for path in paths:
            results.extend(self.match_path(path, correlations))
        return tuple(sorted(results, key=lambda r: r.overall_score, reverse=True))

    def match_path(
        self,
        path: "AttackPath",
        correlations: tuple[Correlation, ...],
    ) -> tuple[TemplateMatchResult, ...]:
        """Convert a graph path to a candidate, then match templates."""
        candidate = self._candidate_from_path(path, correlations)
        if candidate is None:
            return ()
        return self.match_candidate(candidate, correlations)

    def _candidate_from_path(
        self,
        path: "AttackPath",
        correlations: tuple[Correlation, ...],
    ) -> "ChainCandidate | None":
        from .chain_candidate import ChainCandidate

        path_relationships = set(path.relationship_ids)
        path_entities = set(path.entity_ids)
        matched = tuple(
            sorted(
                (
                    correlation
                    for correlation in correlations
                    if path_relationships & set(correlation.matched_relationships)
                    and path_entities & {
                        str(entity["id"])
                        for entity in correlation.matched_entities
                        if "id" in entity
                    }
                ),
                key=lambda item: self._path_order(item, path.relationship_ids),
            )
        )
        if len(matched) < 1:
            return None

        correlation_ids = tuple(correlation.id for correlation in matched)
        edges = tuple(
            edge
            for left, right in zip(matched, matched[1:])
            for edge in self._candidate_edges(left, right)
        )
        if not edges and len(matched) > 1:
            return None

        return ChainCandidate(
            correlation_ids=correlation_ids,
            edges=edges,
            entities=tuple(sorted(path_entities)),
            rule_id=path.template_id or "ATTACK-CHAIN-GENERIC",
        )

    def _candidate_edges(
        self,
        left: Correlation,
        right: Correlation,
    ) -> tuple[ChainEdge, ...]:
        shared = self._entity_map(left).items() & self._entity_map(right).items()
        return tuple(
            ChainEdge(
                from_correlation_id=left.id,
                to_correlation_id=right.id,
                shared_entity_id=entity_id,
                shared_entity_type=entity_type,
                affinity_score=affinity_score(entity_type),
                reason=f"Shared {entity_type} entity",
            )
            for entity_id, entity_type in sorted(shared)
        )

    def _entity_map(self, correlation: Correlation) -> dict[str, str]:
        return {
            str(entity["id"]): str(entity.get("type", "UNKNOWN"))
            for entity in correlation.matched_entities
            if "id" in entity
        }

    def _path_order(
        self,
        correlation: Correlation,
        relationship_ids: tuple[str, ...],
    ) -> tuple[int, str]:
        positions = [
            relationship_ids.index(relationship_id)
            for relationship_id in correlation.matched_relationships
            if relationship_id in relationship_ids
        ]
        return (min(positions, default=len(relationship_ids)), correlation.id)

    def _score_candidate(
        self,
        template: AttackTemplate,
        candidate: "ChainCandidate",
        correlations: tuple[Correlation, ...],
    ) -> TemplateMatchResult:
        """Score a candidate against a template."""

        # Check MITRE technique sequence match
        mitre_score = self._score_mitre_sequence(template, candidate, correlations)

        # Check entity coverage
        entity_score = self._score_entity_coverage(template, candidate, correlations)

        # Check finding coverage
        finding_score = self._score_finding_coverage(template, candidate, correlations)

        # Check entry point match
        entry_point_match = self._check_entry_point(template, candidate, correlations)

        # Weighted overall score
        overall = (
            mitre_score * 0.4 +
            entity_score * 0.4 +
            finding_score * 0.1 +
            (1.0 if entry_point_match else 0.0) * 0.1
        )

        return TemplateMatchResult(
            template=template,
            candidate=type(candidate)(
                correlation_ids=candidate.correlation_ids,
                edges=candidate.edges,
                entities=candidate.entities,
                rule_id=template.id,
            ),
            mitre_sequence_match=mitre_score,
            entity_coverage=entity_score,
            finding_coverage=finding_score,
            entry_point_match=entry_point_match,
            overall_score=overall,
        )

    def _score_mitre_sequence(
        self,
        template: AttackTemplate,
        candidate: "ChainCandidate",
        correlations: tuple[Correlation, ...],
    ) -> float:
        """Score how well the candidate's MITRE chain matches the template."""
        if not template.mitre_chain:
            return 1.0  # No MITRE requirement

        # Collect all MITRE techniques from correlations in the candidate
        corr_by_id = {c.id: c for c in correlations}
        candidate_techniques = []
        for corr_id in candidate.correlation_ids:
            corr = corr_by_id.get(corr_id)
            if corr and corr.mitre:
                candidate_techniques.extend(corr.mitre)

        if not candidate_techniques:
            return 0.0

        # Check subsequence match
        template_techniques = list(template.mitre_chain)
        matches = 0
        for tech in template_techniques:
            if tech in candidate_techniques:
                matches += 1

        return matches / len(template_techniques)

    def _score_entity_coverage(
        self,
        template: AttackTemplate,
        candidate: "ChainCandidate",
        correlations: tuple[Correlation, ...],
    ) -> float:
        """Score how well the candidate covers required entity types."""
        if not template.required_entities:
            return 1.0

        corr_by_id = {c.id: c for c in correlations}
        candidate_entity_types = set()
        for corr_id in candidate.correlation_ids:
            corr = corr_by_id.get(corr_id)
            if corr:
                for entity in corr.matched_entities:
                    if "type" in entity:
                        candidate_entity_types.add(entity["type"])
                    elif "entity_type" in entity:
                        candidate_entity_types.add(entity["entity_type"])

        if not candidate_entity_types:
            return 0.0

        required = set(template.required_entities)
        covered = required & candidate_entity_types
        return len(covered) / len(required)

    def _score_finding_coverage(
        self,
        template: AttackTemplate,
        candidate: "ChainCandidate",
        correlations: tuple[Correlation, ...],
    ) -> float:
        """Score how well the candidate covers required findings."""
        if not template.required_findings:
            return 1.0

        corr_by_id = {c.id: c for c in correlations}
        candidate_findings = set()
        for corr_id in candidate.correlation_ids:
            corr = corr_by_id.get(corr_id)
            if corr:
                candidate_findings.update(corr.supporting_findings)

        required = set(template.required_findings)
        covered = required & candidate_findings
        return len(covered) / len(required)

    def _check_entry_point(
        self,
        template: AttackTemplate,
        candidate: "ChainCandidate",
        correlations: tuple[Correlation, ...],
    ) -> bool:
        """Check if the candidate's entry point matches the template's entry point type."""
        corr_by_id = {c.id: c for c in correlations}

        # Find entry point correlation (no incoming edges)
        successors = {edge.to_correlation_id for edge in candidate.edges}
        entry_corr_ids = [cid for cid in candidate.correlation_ids if cid not in successors]

        if not entry_corr_ids:
            return False

        entry_corr = corr_by_id.get(entry_corr_ids[0])
        if not entry_corr:
            return False

        # Check if any matched entity matches the entry point type
        for entity in entry_corr.matched_entities:
            if entity.get("type") == template.entry_point_type:
                return True

        return False
