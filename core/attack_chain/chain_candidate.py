"""
core.chain_candidate
====================

Temporary connected component discovered by DFS.
"""

from __future__ import annotations

from dataclasses import dataclass

from .chain_edge import ChainEdge

__all__ = ["ChainCandidate"]


@dataclass(frozen=True)
class ChainCandidate:
    """Candidate attack chain before validation."""

    correlation_ids: tuple[str, ...]
    edges: tuple[ChainEdge, ...]
    entities: tuple[str, ...]
    rule_id: str = "ATTACK-CHAIN-GENERIC"
