"""
core.dashboard_view
===================

Milestone 10 dashboard view contract.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["DashboardView"]


class DashboardView(Enum):
    """Supported dashboard views."""

    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    RISK_PRIORITY = "RISK_PRIORITY"
    ATTACK_CHAINS = "ATTACK_CHAINS"
    CORRELATIONS = "CORRELATIONS"
    KNOWLEDGE_GRAPH = "KNOWLEDGE_GRAPH"
    MITRE_MATRIX = "MITRE_MATRIX"
    EVIDENCE_EXPLORER = "EVIDENCE_EXPLORER"
