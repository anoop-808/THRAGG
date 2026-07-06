"""
core.executive.posture_calculator
=================================

Deterministic security posture calculation from RiskAssessment objects.
"""

from __future__ import annotations

from ..risk.risk_assessment import RiskAssessment
from .security_posture import SecurityPosture

__all__ = ["PostureCalculator"]


class PostureCalculator:
    """Calculate overall posture using frozen score thresholds."""

    EXCELLENT_MAX = 24
    GOOD_MAX = 49
    FAIR_MAX = 69
    POOR_MAX = 89

    def calculate(self, risks: tuple[RiskAssessment, ...]) -> SecurityPosture:
        """Return the posture label for the highest effective risk score."""
        highest = max((risk.score for risk in risks), default=0)
        if highest <= self.EXCELLENT_MAX:
            return SecurityPosture.EXCELLENT
        if highest <= self.GOOD_MAX:
            return SecurityPosture.GOOD
        if highest <= self.FAIR_MAX:
            return SecurityPosture.FAIR
        if highest <= self.POOR_MAX:
            return SecurityPosture.POOR
        return SecurityPosture.CRITICAL_BUSINESS
