"""
core.security_posture
=====================

Security posture labels for Milestone 8 executive assessment contracts.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["SecurityPosture"]


class SecurityPosture(str, Enum):
    """Executive posture labels produced by deterministic M8 logic."""

    HEALTHY = "HEALTHY"
    OBSERVE = "OBSERVE"
    ELEVATED = "ELEVATED"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"
