"""
core.risk_level
===============

Risk level labels for Milestone 7 assessments.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["RiskLevel"]


class RiskLevel(str, Enum):
    """Risk level labels derived from final score."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
