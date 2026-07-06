"""
core.executive.recommendation_registry
======================================

Deterministic executive recommendation catalog.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

__all__ = ["Recommendation", "RecommendationRegistry"]


@dataclass(frozen=True)
class Recommendation:
    """One reusable executive recommendation."""

    id: str
    title: str
    description: str
    priority: str
    business_reason: str
    technical_reason: str
    expected_benefit: str
    references: tuple[str, ...]
    match_terms: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "references", tuple(self.references))
        object.__setattr__(self, "match_terms", tuple(self.match_terms))

    def to_dict(self) -> dict[str, Any]:
        """Serialize public recommendation fields."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "business_reason": self.business_reason,
            "technical_reason": self.technical_reason,
            "expected_benefit": self.expected_benefit,
            "references": list(self.references),
        }


class RecommendationRegistry:
    """Static recommendation registry used by the executive layer."""

    PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

    def __init__(self, recommendations: tuple[Recommendation, ...] | None = None) -> None:
        self._recommendations = recommendations or DEFAULT_RECOMMENDATIONS

    def all(self) -> tuple[Recommendation, ...]:
        """Return recommendations in deterministic order."""
        return tuple(sorted(self._recommendations, key=lambda item: item.id))

    def matching(self, text: str) -> tuple[Recommendation, ...]:
        """Return recommendations whose registry terms match the supplied text."""
        lowered = text.lower()
        matches = [
            recommendation
            for recommendation in self.all()
            if any(term in lowered for term in recommendation.match_terms)
        ]
        return self.order(tuple(matches)) or (self.get("REC-GOV-001"),)

    def order(
        self,
        recommendations: tuple[Recommendation, ...],
    ) -> tuple[Recommendation, ...]:
        """Return recommendations ordered by registry priority then id."""
        return tuple(
            sorted(
                recommendations,
                key=lambda item: (self.PRIORITY_ORDER.get(item.priority, 99), item.id),
            )
        )

    def get(self, recommendation_id: str) -> Recommendation:
        """Return one recommendation by id."""
        for recommendation in self._recommendations:
            if recommendation.id == recommendation_id:
                return recommendation
        raise KeyError(recommendation_id)


DEFAULT_RECOMMENDATIONS = (
    Recommendation(
        id="REC-IAM-001",
        title="Review Privileged Identity Exposure",
        description="Reduce exposure around privileged identities and authentication paths.",
        priority="High",
        business_reason="Privileged access can affect core business systems.",
        technical_reason="Risk input references identity or administrative access exposure.",
        expected_benefit="Lower likelihood of unauthorized access to critical services.",
        references=("NIST CSF PR.AC", "CIS Controls 5"),
        match_terms=("identity", "admin", "administrator", "privilege", "authentication"),
    ),
    Recommendation(
        id="REC-NET-001",
        title="Restrict Remote Administrative Access",
        description="Limit remote administration paths to approved trusted access channels.",
        priority="High",
        business_reason="Remote access exposure increases the chance of business disruption.",
        technical_reason="Risk input references SSH or remote administrative access.",
        expected_benefit="Reduced external exposure of management services.",
        references=("CIS Controls 12", "NIST CSF PR.AC"),
        match_terms=("ssh", "remote", "administrative access"),
    ),
    Recommendation(
        id="REC-CLD-001",
        title="Reduce Cloud Service Exposure",
        description="Review externally reachable cloud services and apply least exposure.",
        priority="Medium",
        business_reason="Externally reachable services can expose business operations.",
        technical_reason="Risk input references public cloud or cloud service exposure.",
        expected_benefit="Reduced public attack surface for cloud-hosted services.",
        references=("CIS Controls 4", "NIST CSF PR.PT"),
        match_terms=("cloud", "public", "azure", "storage account", "key vault"),
    ),
    Recommendation(
        id="REC-GOV-001",
        title="Track Risk Owner Follow-up",
        description="Assign ownership for the Risk Engine suggested action and verify closure.",
        priority="Medium",
        business_reason="Clear ownership keeps material risks from remaining unresolved.",
        technical_reason="Risk input includes a suggested action requiring follow-up.",
        expected_benefit="Improved accountability for reducing assessed risk.",
        references=("NIST CSF GV.RM",),
        match_terms=("review", "remediate", "reduce", "monitor", "restrict"),
    ),
)
