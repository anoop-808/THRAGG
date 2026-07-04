"""
core.attack_chain_builder
=========================

Construction-only builder for AttackChain objects.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .attack_chain import AttackChain
from .chain_candidate import ChainCandidate
from .chain_discovery_engine import stage_sort_key
from .correlation import Correlation
from .finding import Confidence, Severity
from .stable_id import stable_sha_id

__all__ = ["AttackChainBuilder", "stable_attack_chain_id"]

SEVERITY_PRIORITY = {
    Severity.CRITICAL: 3,
    Severity.HIGH: 2,
    Severity.MEDIUM: 1,
    Severity.LOW: 0,
}


def stable_attack_chain_id(correlation_ids: tuple[str, ...]) -> str:
    """Return deterministic id from sorted correlation ids."""
    return stable_sha_id("chain", *sorted(correlation_ids))


class AttackChainBuilder:
    """Build AttackChain objects from validated candidates."""

    def build(
        self,
        candidate: ChainCandidate,
        correlations: tuple[Correlation, ...],
    ) -> AttackChain:
        """Construct one AttackChain. No traversal, evaluation, or validation."""
        by_id = {correlation.id: correlation for correlation in correlations}
        chain_correlations = tuple(
            sorted(
                (by_id[item_id] for item_id in candidate.correlation_ids),
                key=stage_sort_key,
            )
        )
        entry_point = self._entry_point(candidate, chain_correlations)
        target = self._target(candidate, chain_correlations)
        return AttackChain(
            id=stable_attack_chain_id(candidate.correlation_ids),
            title=self._title(chain_correlations),
            description=self._description(chain_correlations),
            severity=self._highest_severity(chain_correlations),
            confidence=(
                chain_correlations[0].confidence
                if chain_correlations
                else Confidence.LOW
            ),
            entry_point=entry_point,
            target=target,
            timeline=self._timeline(chain_correlations),
            correlations=tuple(correlation.id for correlation in chain_correlations),
            chain_edges=candidate.edges,
            entities=candidate.entities,
            relationships=self._relationships(chain_correlations),
            supporting_findings=self._supporting_findings(chain_correlations),
            recommendations=self._recommendations(chain_correlations),
            created_at=datetime.now(UTC).replace(microsecond=0).isoformat(),
        )

    def _title(self, correlations: tuple[Correlation, ...]) -> str:
        if not correlations:
            return "Attack chain"
        first_title = correlations[0].title
        last_title = correlations[-1].title
        if first_title == last_title:
            return first_title
        return f"{first_title} → {last_title}"

    def _description(self, correlations: tuple[Correlation, ...]) -> str:
        stages = tuple(self._stage_label(correlation) for correlation in correlations)
        stage_word = "stage" if len(stages) == 1 else "stages"
        stages_text = " → ".join(stages)
        return f"Attack chain spanning {len(stages)} {stage_word}: {stages_text}"

    def _highest_severity(
        self,
        correlations: tuple[Correlation, ...],
    ) -> Severity:
        if not correlations:
            return Severity.LOW
        highest = max(
            correlations,
            key=lambda item: SEVERITY_PRIORITY[item.severity],
        )
        return highest.severity

    def _entry_point(
        self,
        candidate: ChainCandidate,
        correlations: tuple[Correlation, ...],
    ) -> str:
        successors = {edge.to_correlation_id for edge in candidate.edges}
        return next(
            correlation.id for correlation in correlations if correlation.id not in successors
        )

    def _target(
        self,
        candidate: ChainCandidate,
        correlations: tuple[Correlation, ...],
    ) -> str:
        predecessors = {edge.from_correlation_id for edge in candidate.edges}
        return next(
            correlation.id
            for correlation in reversed(correlations)
            if correlation.id not in predecessors
        )

    def _timeline(
        self,
        correlations: tuple[Correlation, ...],
    ) -> tuple[dict[str, str], ...]:
        return tuple(
            {
                "stage": str(
                    correlation.correlation_explanation.get("stage", "DISCOVERY")
                ),
                "timestamp": correlation.timestamp,
                "correlation_id": correlation.id,
            }
            for correlation in correlations
        )

    def _relationships(
        self,
        correlations: tuple[Correlation, ...],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    relationship_id
                    for correlation in correlations
                    for relationship_id in correlation.matched_relationships
                }
            )
        )

    def _supporting_findings(
        self,
        correlations: tuple[Correlation, ...],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    finding_id
                    for correlation in correlations
                    for finding_id in correlation.supporting_findings
                }
            )
        )

    def _recommendations(
        self,
        correlations: tuple[Correlation, ...],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    correlation.recommendation
                    for correlation in correlations
                    if correlation.recommendation.strip()
                }
            )
        )

    def _stage_label(self, correlation: Correlation) -> str:
        stage = str(correlation.correlation_explanation.get("stage", "DISCOVERY"))
        return stage.replace("_", " ").title()
