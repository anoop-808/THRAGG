"""
core.attack_chain_schema
========================

Structural validation for AttackChain objects.
"""

from __future__ import annotations

from .attack_chain import AttackChain
from .chain_edge import ChainEdge
from .finding import Confidence, Severity

__all__ = [
    "AttackChainSchemaError",
    "validate_attack_chain",
    "is_valid_attack_chain",
]


class AttackChainSchemaError(ValueError):
    """Raised when an AttackChain fails structural validation."""


def validate_attack_chain(chain: AttackChain) -> None:
    """Validate an AttackChain without mutating it."""
    for field_name in ("id", "title", "description", "entry_point", "target", "created_at"):
        value = getattr(chain, field_name)
        if not isinstance(value, str) or not value.strip():
            raise AttackChainSchemaError(
                f"AttackChain.{field_name} must be a non-empty string"
            )
    if not isinstance(chain.severity, Severity):
        raise AttackChainSchemaError("AttackChain.severity must be a Severity enum")
    if not isinstance(chain.confidence, Confidence):
        raise AttackChainSchemaError("AttackChain.confidence must be a Confidence enum")
    if not isinstance(chain.chain_edges, tuple) or not all(
        isinstance(edge, ChainEdge) for edge in chain.chain_edges
    ):
        raise AttackChainSchemaError("AttackChain.chain_edges must be tuple[ChainEdge]")
    _strings(chain.correlations, "correlations")
    _strings(chain.entities, "entities")
    _strings(chain.relationships, "relationships")
    _strings(chain.supporting_findings, "supporting_findings")
    _strings(chain.recommendations, "recommendations")
    if not isinstance(chain.timeline, tuple) or not all(
        isinstance(item, dict) for item in chain.timeline
    ):
        raise AttackChainSchemaError("AttackChain.timeline must be tuple[dict]")


def is_valid_attack_chain(chain: AttackChain) -> bool:
    """Return True when an AttackChain passes schema validation."""
    try:
        validate_attack_chain(chain)
        return True
    except AttackChainSchemaError:
        return False


def _strings(value: object, field_name: str) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise AttackChainSchemaError(
            f"AttackChain.{field_name} must be a tuple of non-empty strings"
        )
