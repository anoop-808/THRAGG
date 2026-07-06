"""
core.attack_chain_builder
=========================

Construction-only builder for AttackChain objects.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .attack_chain import AttackChain
from .attack_step import AttackStep
from .chain_candidate import ChainCandidate
from .chain_discovery_engine import stage_sort_key
from ..correlation.correlation import Correlation
from ..foundation.finding import Confidence, Severity
from ..shared.stable_id import stable_sha_id

__all__ = ["AttackChainBuilder", "stable_attack_chain_id"]

SEVERITY_PRIORITY = {
    Severity.CRITICAL: 3,
    Severity.HIGH: 2,
    Severity.MEDIUM: 1,
    Severity.LOW: 0,
}
CONFIDENCE_POINTS = {
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
}
MEDIUM_CONFIDENCE_SCORE = 7 / 12
HIGH_CONFIDENCE_SCORE = 10 / 12
# ponytail: legacy correlations may lack MITRE; remove when correlation MITRE is mandatory.
LEGACY_MITRE_PLACEHOLDER = "T0000"


def stable_attack_chain_id(correlation_ids: tuple[str, ...]) -> str:
    """Return deterministic id from sorted correlation ids."""
    return stable_sha_id("chain", *sorted(correlation_ids))


class AttackChainBuilder:
    """Build AttackChain objects from validated candidates."""

    def build(
        self,
        candidate: ChainCandidate,
        correlations: tuple[Correlation, ...],
        template_match_score: float | None = None,
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
        confidence_score = (
            self._confidence_score(chain_correlations, template_match_score)
            if template_match_score is not None
            else None
        )
        return AttackChain(
            chain_id=stable_attack_chain_id(candidate.correlation_ids),
            id=stable_attack_chain_id(candidate.correlation_ids),
            title=self._title(chain_correlations),
            description=self._description(chain_correlations),
            severity=self._highest_severity(chain_correlations),
            confidence=(
                self._confidence_label(confidence_score)
                if confidence_score is not None
                else self._legacy_confidence(chain_correlations)
            ),
            entry_point=entry_point,
            target=target,
            steps=self._steps(chain_correlations),
            timeline=self._timeline(chain_correlations),
            correlations=tuple(correlation.id for correlation in chain_correlations),
            chain_edges=candidate.edges,
            participating_entities=candidate.entities,
            entities=candidate.entities,
            participating_relationships=self._relationships(chain_correlations),
            relationships=self._relationships(chain_correlations),
            supporting_findings=self._supporting_findings(chain_correlations),
            mitre_techniques=self._mitre_techniques(chain_correlations),
            template_id=candidate.rule_id,
            metadata=self._metadata(
                chain_correlations,
                template_match_score,
                confidence_score,
            ),
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

    def _legacy_confidence(self, correlations: tuple[Correlation, ...]) -> Confidence:
        return correlations[0].confidence if correlations else Confidence.LOW

    def _confidence_score(
        self,
        correlations: tuple[Correlation, ...],
        template_match_score: float,
    ) -> float:
        correlation_score = (
            sum(CONFIDENCE_POINTS[item.confidence] for item in correlations)
            / len(correlations)
            / max(CONFIDENCE_POINTS.values())
            if correlations
            else 0.0
        )
        evidence_score = min(len(self._supporting_findings(correlations)), 5) / 5
        return (
            (correlation_score * 0.4)
            + (max(0.0, min(template_match_score, 1.0)) * 0.4)
            + (evidence_score * 0.2)
        )

    def _confidence_label(self, score: float) -> Confidence:
        if score >= HIGH_CONFIDENCE_SCORE:
            return Confidence.HIGH
        if score >= MEDIUM_CONFIDENCE_SCORE:
            return Confidence.MEDIUM
        return Confidence.LOW

    def _metadata(
        self,
        correlations: tuple[Correlation, ...],
        template_match_score: float | None,
        confidence_score: float | None,
    ) -> dict[str, Any]:
        if confidence_score is None or template_match_score is None:
            return {}
        return {
            "confidence_model": "attack_chain_v1",
            "confidence_score": confidence_score,
            "confidence_factors": {
                "correlation_confidence": (
                    sum(CONFIDENCE_POINTS[item.confidence] for item in correlations)
                    / len(correlations)
                    / max(CONFIDENCE_POINTS.values())
                    if correlations
                    else 0.0
                ),
                "template_match_score": max(0.0, min(template_match_score, 1.0)),
                "evidence_count": len(self._supporting_findings(correlations)),
            },
        }

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
    ) -> tuple[dict[str, Any], ...]:
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

    def _steps(self, correlations: tuple[Correlation, ...]) -> tuple[AttackStep, ...]:
        return tuple(
            AttackStep(
                step_number=index,
                technique=self._stage_label(correlation),
                mitre_id=correlation.mitre[0] if correlation.mitre else LEGACY_MITRE_PLACEHOLDER,
                entity=self._first_entity_id(correlation),
                evidence=correlation.supporting_findings,
                description=correlation.description,
                confidence=correlation.confidence,
                step_id=f"{correlation.id}-step-{index}",
                correlation_id=correlation.id,
                stage=str(correlation.correlation_explanation.get("stage", "DISCOVERY")),
                entities=tuple(
                    str(entity["id"])
                    for entity in correlation.matched_entities
                    if "id" in entity
                ),
                relationships=correlation.matched_relationships,
                supporting_findings=correlation.supporting_findings,
                mitre_techniques=correlation.mitre or (LEGACY_MITRE_PLACEHOLDER,),
            )
            for index, correlation in enumerate(correlations, start=1)
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

    def _mitre_techniques(
        self,
        correlations: tuple[Correlation, ...],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    technique
                    for correlation in correlations
                    for technique in correlation.mitre or (LEGACY_MITRE_PLACEHOLDER,)
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

    def _first_entity_id(self, correlation: Correlation) -> str:
        return next(
            (
                str(entity["id"])
                for entity in correlation.matched_entities
                if "id" in entity
            ),
            "",
        )
