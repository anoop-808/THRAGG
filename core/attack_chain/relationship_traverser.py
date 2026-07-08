"""
core.relationship_traverser
==========================

Traverse the RelationshipGraph to find attack paths.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .attack_template import AttackTemplate
from ..foundation.relationship_graph import RelationshipGraph
from ..foundation.resolved_entity import ResolvedEntity

if TYPE_CHECKING:
    from .chain_candidate import ChainCandidate
    from ..correlation.correlation import Correlation

__all__ = [
    "RelationshipTraverser",
    "AttackPath",
    "EntryPoint",
    "TraversalResult",
]


@dataclass(frozen=True)
class EntryPoint:
    """An identified attacker entry point in the graph."""

    entity_id: str
    entity_type: str
    exposure_type: str  # PUBLIC, EXPOSED, INTERNET_FACING, etc.
    confidence: float   # 0.0 - 1.0
    supporting_findings: tuple[str, ...]


@dataclass(frozen=True)
class AttackPath:
    """A path through the relationship graph representing potential attacker progression."""

    entity_ids: tuple[str, ...]           # Ordered entity IDs in the path
    relationship_ids: tuple[str, ...]     # Relationship IDs connecting entities
    entry_point: EntryPoint
    mitre_techniques: tuple[str, ...]
    template_id: str | None = None
    confidence: float = 0.0


@dataclass(frozen=True)
class TraversalResult:
    """Result of graph traversal for attack path discovery."""

    paths: tuple[AttackPath, ...]
    entry_points: tuple[EntryPoint, ...]
    covered_entities: tuple[str, ...]


class RelationshipTraverser:
    """Traverse the RelationshipGraph to find attack paths and entry points."""

    def __init__(
        self,
        graph: RelationshipGraph,
        entities: dict[str, ResolvedEntity],
        templates: tuple[AttackTemplate, ...] | None = None,
        max_path_length: int = 10,
    ) -> None:
        self.graph = graph
        self.entities = entities
        self.max_path_length = max_path_length
        if templates is not None:
            self._templates = templates
        else:
            from .attack_template_repository import AttackTemplateRepository
            self._templates = AttackTemplateRepository().list()

    def find_entry_points(self) -> tuple[EntryPoint, ...]:
        """Identify possible attacker entry points in the graph."""
        entry_points = []

        for entity_id in self.graph.nodes():
            entity = self.entities.get(entity_id)
            if not entity:
                continue

            exposure_type = self._determine_exposure(entity)
            if exposure_type:
                confidence = self._calculate_entry_confidence(entity, exposure_type)
                findings = self._get_supporting_findings(entity_id)
                entry_points.append(EntryPoint(
                    entity_id=entity_id,
                    entity_type=entity.entity_type.value if hasattr(entity.entity_type, 'value') else str(entity.entity_type),
                    exposure_type=exposure_type,
                    confidence=confidence,
                    supporting_findings=tuple(findings),
                ))

        return tuple(sorted(entry_points, key=lambda e: e.confidence, reverse=True))

    def _determine_exposure(self, entity: ResolvedEntity) -> str | None:
        """Determine if an entity represents an entry point."""
        attrs = entity.attributes
        entity_type = entity.entity_type.value if hasattr(entity.entity_type, "value") else str(entity.entity_type)

        # Public-facing services
        if entity_type in ("SERVICE", "APPLICATION"):
            if attrs.get("public") is True or attrs.get("internet_facing") is True:
                return "PUBLIC"
            if attrs.get("port") in (22, 80, 443, 3389, 5432, 3306, 27017):
                return "EXPOSED"

        # Public cloud resources
        if entity_type in ("CLOUD_RESOURCE", "STORAGE", "DATABASE"):
            if attrs.get("public") is True:
                return "PUBLIC"

        # Hosts with public IPs
        if entity_type == "HOST":
            if attrs.get("public") is True or attrs.get("public_ip") is not None:
                return "PUBLIC"

        # Identities without MFA
        if entity_type == "IDENTITY":
            if attrs.get("no_mfa") is True:
                return "EXPOSED"

        return None

    def _calculate_entry_confidence(self, entity: ResolvedEntity, exposure_type: str) -> float:
        """Calculate confidence for an entry point."""
        base = 0.5
        if exposure_type == "PUBLIC":
            base = 0.8
        elif exposure_type == "EXPOSED":
            base = 0.6

        # Boost confidence based on findings
        findings_count = len(entity.source_findings or ())
        boost = min(findings_count * 0.05, 0.2)

        return min(base + boost, 1.0)

    def _get_supporting_findings(self, entity_id: str) -> tuple[str, ...]:
        """Get supporting finding IDs for an entity."""
        entity = self.entities.get(entity_id)
        if not entity:
            return ()
        return tuple(entity.source_findings or ())

    def find_attack_paths(
        self,
        entry_points: tuple[EntryPoint, ...] | None = None,
    ) -> tuple[AttackPath, ...]:
        """Find attack paths from entry points through the graph."""
        if entry_points is None:
            entry_points = self.find_entry_points()

        paths = []
        for entry in entry_points:
            paths.extend(self._traverse_from_entry(entry))

        return tuple(sorted(paths, key=lambda p: p.confidence, reverse=True))

    def _traverse_from_entry(self, entry: EntryPoint) -> list[AttackPath]:
        """BFS traversal from an entry point to find attack paths."""
        paths = []
        print(f"Finding paths from {entry.entity_id}")
        queue = deque([(entry.entity_id, (entry.entity_id,), (), 0)])

        while queue:
            current_id, entity_path, rel_path, depth = queue.popleft()
            if len(queue) % 1000 == 0 and len(queue) > 0:
                print(f"Traversal queue size: {len(queue)}, depth: {depth}")

            if depth >= self.max_path_length:
                continue

            # Check if this path matches any template
            if depth >= 1:  # At least one step
                path = self._build_attack_path(entry, entity_path, rel_path)
                if path and path.confidence > 0.3:
                    paths.append(path)

            # Explore neighbors (outgoing)
            for rel in self.graph.outgoing_edges(current_id):
                target_id = rel.target_entity_id
                if target_id in entity_path:
                    continue  # Avoid cycles
                
                # Prevent massive graph explosion among identities: allow at most ONE such edge
                if (
                    rel.source_entity_id.startswith("resolved-identity-") 
                    and target_id.startswith("resolved-identity-") 
                    and rel.relationship_type.name == "RELATED_TO"
                ):
                    # Check if we ALREADY have an identity-to-identity edge in rel_path
                    # By checking if the current_id was reached via such an edge.
                    # Since this is outgoing, if the last edge was also identity-related-to-identity, we skip.
                    if depth > 0:
                        continue

                queue.append((
                    target_id,
                    entity_path + (target_id,),
                    rel_path + (rel.id,),
                    depth + 1,
                ))

            # Explore neighbors (incoming) - ONLY traverse EXPOSES backwards to prevent explosion
            for rel in self.graph.incoming_edges(current_id):
                if rel.relationship_type.name != "EXPOSES":
                    continue
                target_id = rel.source_entity_id
                if target_id in entity_path:
                    continue  # Avoid cycles

                queue.append((
                    target_id,
                    entity_path + (target_id,),
                    rel_path + (rel.id,),
                    depth + 1,
                ))

        return paths

    def _build_attack_path(
        self,
        entry: EntryPoint,
        entity_path: tuple[str, ...],
        rel_path: tuple[str, ...],
    ) -> AttackPath | None:
        """Build an AttackPath from a traversal path."""
        if len(entity_path) < 2:
            return None

        # Collect MITRE techniques from relationships
        mitre_techniques = []
        for rel_id in rel_path:
            rel = self.graph.get_relationship(rel_id)
            mitre_techniques.extend(getattr(rel, "mitre_techniques", ()) or ())

        # Match against templates
        template_id = self._match_template(entity_path, mitre_techniques)

        # Calculate path confidence
        confidence = self._calculate_path_confidence(entry, entity_path, rel_path, mitre_techniques)

        if confidence < 0.3:
            return None

        return AttackPath(
            entity_ids=entity_path,
            relationship_ids=rel_path,
            entry_point=entry,
            mitre_techniques=tuple(dict.fromkeys(mitre_techniques)),
            template_id=template_id,
            confidence=confidence,
        )

    def _match_template(
        self,
        entity_path: tuple[str, ...],
        mitre_techniques: list[str],
    ) -> str | None:
        """Match a path against attack templates."""
        entity_types = []
        for eid in entity_path:
            entity = self.entities.get(eid)
            if entity:
                et = entity.entity_type.value if hasattr(entity.entity_type, 'value') else str(entity.entity_type)
                entity_types.append(et)

        best_match = None
        best_score = 0.0

        for template in self._templates:
            score = 0.0

            # Check entity type sequence
            if template.required_entities:
                matches = sum(1 for req in template.required_entities if req in entity_types)
                score += matches / len(template.required_entities) * 0.5

            # Check MITRE sequence
            if template.mitre_chain:
                matches = sum(1 for mitre in template.mitre_chain if mitre in mitre_techniques)
                score += matches / len(template.mitre_chain) * 0.5

            if score > best_score:
                best_score = score
                best_match = template.id

        return best_match if best_score > 0.3 else None

    def _calculate_path_confidence(
        self,
        entry: EntryPoint,
        entity_path: tuple[str, ...],
        rel_path: tuple[str, ...],
        mitre_techniques: list[str],
    ) -> float:
        """Calculate confidence for an attack path."""
        # Start with entry point confidence
        confidence = entry.confidence * 0.4

        # Add relationship confidence
        rel_confidences = []
        for rel_id in rel_path:
            rel = self.graph.get_relationship(rel_id)
            if rel and hasattr(rel, 'confidence_contribution'):
                rel_confidences.append(rel.confidence_contribution)

        if rel_confidences:
            confidence += (sum(rel_confidences) / len(rel_confidences)) * 0.4

        # Add MITRE technique coverage bonus
        if mitre_techniques:
            confidence += min(len(mitre_techniques) * 0.05, 0.2)

        return min(confidence, 1.0)

    def traverse(self) -> TraversalResult:
        """Full traversal: find entry points and attack paths."""
        entry_points = self.find_entry_points()
        paths = self.find_attack_paths(entry_points)

        covered = set()
        for path in paths:
            covered.update(path.entity_ids)

        return TraversalResult(
            paths=paths,
            entry_points=entry_points,
            covered_entities=tuple(sorted(covered)),
        )
