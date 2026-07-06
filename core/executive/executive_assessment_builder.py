"""
core.executive_assessment_builder
=================================

Build structured executive assessments from intelligence objects.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from ..foundation.finding import Confidence, Severity
from ..risk.risk_level import RiskLevel
from ..shared.traceability_map import TraceabilityMap
from .executive_assessment import ExecutiveAssessment, stable_executive_assessment_id
from .executive_schema import validate_executive_assessment
from .framework_snapshot import FrameworkSnapshot
from .framework_statistics import CountMetric, FrameworkStatistics
from .observation import Observation, ObservationCategory
from .security_posture import SecurityPosture

__all__ = ["ExecutiveAssessmentBuilder"]


class ExecutiveAssessmentBuilder:
    """Translate scored intelligence into executive language."""

    def __init__(self, engine_version: str = "intelligence-v1") -> None:
        self.engine_version = engine_version

    def build(
        self,
        snapshot: FrameworkSnapshot,
        generated_at: str | None = None,
    ) -> ExecutiveAssessment:
        """Build one structured executive assessment."""
        generated_at = (
            generated_at or datetime.now(UTC).replace(microsecond=0).isoformat()
        )
        observations = self._observations(snapshot)
        assessment = ExecutiveAssessment(
            id=stable_executive_assessment_id(
                snapshot.snapshot_version,
                snapshot.generated_at,
                self.engine_version,
            ),
            summary=self._summary(snapshot),
            observations=observations,
            recommendations=self._recommendations(snapshot),
            statistics=self._statistics(snapshot),
            security_posture=self._posture(snapshot),
            traceability=self._traceability(snapshot, observations),
            engine_version=self.engine_version,
            generated_at=generated_at,
        )
        validate_executive_assessment(assessment)
        return assessment

    def _summary(self, snapshot: FrameworkSnapshot) -> str:
        if not snapshot.risk_assessments:
            return "No scored attack paths were identified in the current assessment."
        highest = max(snapshot.risk_assessments, key=lambda risk: risk.score)
        return (
            f"{highest.risk_level.value.title()} environmental risk is driven by "
            f"{len(snapshot.attack_chains)} attack path(s) across "
            f"{snapshot.entity_count} known asset(s)."
        )

    def _observations(self, snapshot: FrameworkSnapshot) -> tuple[Observation, ...]:
        observations: list[Observation] = []
        for index, risk in enumerate(
            sorted(snapshot.risk_assessments, key=lambda item: (-item.score, item.id))[:5],
            start=1,
        ):
            chain = next(
                (
                    item
                    for item in snapshot.attack_chains
                    if item.id == risk.attack_chain_id
                ),
                None,
            )
            observations.append(
                Observation(
                    id=f"obs-{index}",
                    category=ObservationCategory.EXPOSURE,
                    severity=_severity(risk.risk_level),
                    confidence=chain.confidence if chain else Confidence.MEDIUM,
                    text=f"{risk.risk_level.value.title()} risk attack path: {chain.title if chain else risk.attack_chain_id}.",
                    supporting_object_ids=(
                        risk.id,
                        risk.attack_chain_id,
                        *(chain.correlations if chain else ()),
                    ),
                )
            )
        return tuple(observations)

    def _recommendations(self, snapshot: FrameworkSnapshot) -> tuple[str, ...]:
        recommendations = {
            item.recommendation
            for item in snapshot.risk_assessments
            if item.recommendation.strip()
        }
        return tuple(sorted(recommendations)) or ("Continue monitoring correlated attack paths.",)

    def _statistics(self, snapshot: FrameworkSnapshot) -> FrameworkStatistics:
        risk_counts = Counter(item.risk_level.value for item in snapshot.risk_assessments)
        entity_types = Counter(
            str(entity.get("entity_type", "UNKNOWN"))
            for correlation in snapshot.correlations
            for entity in correlation.matched_entities
        )
        stages = Counter(
            str(correlation.correlation_explanation.get("stage", "DISCOVERY"))
            for correlation in snapshot.correlations
        )
        categories = Counter(correlation.category for correlation in snapshot.correlations)
        return FrameworkStatistics(
            total_findings=snapshot.finding_count,
            total_entities=snapshot.entity_count,
            total_relationships=snapshot.relationship_count,
            total_correlations=len(snapshot.correlations),
            total_attack_chains=len(snapshot.attack_chains),
            risk_counts=_metrics(risk_counts),
            top_entity_types=_metrics(entity_types),
            top_attack_stages=_metrics(stages),
            top_attack_categories=_metrics(categories),
        )

    def _posture(self, snapshot: FrameworkSnapshot) -> SecurityPosture:
        highest = max((risk.score for risk in snapshot.risk_assessments), default=0)
        if highest >= 90:
            return SecurityPosture.CRITICAL
        if highest >= 70:
            return SecurityPosture.HIGH_RISK
        if highest >= 50:
            return SecurityPosture.ELEVATED
        if highest >= 25:
            return SecurityPosture.OBSERVE
        return SecurityPosture.HEALTHY

    def _traceability(
        self,
        snapshot: FrameworkSnapshot,
        observations: tuple[Observation, ...],
    ) -> TraceabilityMap:
        risk_by_id = {risk.id: risk for risk in snapshot.risk_assessments}
        chains_by_id = {chain.id: chain for chain in snapshot.attack_chains}
        return TraceabilityMap(
            observation_to_risks=tuple(
                (obs.id, tuple(item for item in obs.supporting_object_ids if item in risk_by_id))
                for obs in observations
            ),
            observation_to_attack_chains=tuple(
                (obs.id, tuple(item for item in obs.supporting_object_ids if item in chains_by_id))
                for obs in observations
            ),
            observation_to_correlations=tuple(
                (
                    obs.id,
                    tuple(
                        item
                        for item in obs.supporting_object_ids
                        if item.startswith("corr-")
                    ),
                )
                for obs in observations
            ),
            recommendation_to_observations=tuple(
                (recommendation, tuple(obs.id for obs in observations))
                for recommendation in self._recommendations(snapshot)
            ),
        )


def _metrics(counter: Counter[str]) -> tuple[CountMetric, ...]:
    return tuple(
        CountMetric(name, count)
        for name, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    )


def _severity(level: RiskLevel) -> Severity:
    if level is RiskLevel.CRITICAL:
        return Severity.CRITICAL
    if level is RiskLevel.HIGH:
        return Severity.HIGH
    if level is RiskLevel.MEDIUM:
        return Severity.MEDIUM
    return Severity.LOW
