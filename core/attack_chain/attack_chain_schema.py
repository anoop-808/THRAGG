"""
core.attack_chain_schema
========================

Structural validation for AttackChain objects.
"""

from __future__ import annotations

from collections.abc import Mapping

from .attack_chain import AttackChain
from .attack_chain_validator import AttackChainValidationError, AttackChainValidator
from .attack_step import AttackStep
from .attack_template import AttackTemplate
from .chain_edge import ChainEdge
from ..foundation.finding import Confidence, Severity

__all__ = [
    "AttackChainSchema",
    "AttackChainSchemaError",
    "validate_attack_chain",
    "validate_attack_template",
    "is_valid_attack_chain",
]


class AttackChainSchemaError(ValueError):
    """Raised when an AttackChain fails structural validation."""


def validate_attack_chain(chain: AttackChain) -> None:
    """Validate an AttackChain without mutating it."""
    if not isinstance(chain, AttackChain):
        raise AttackChainSchemaError("chain must be an AttackChain")
    for field_name in ("id", "title", "description", "entry_point", "target", "created_at"):
        value = getattr(chain, field_name)
        if field_name in {"title", "target", "created_at"} and not value:
            continue
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
    _strings(chain.participating_entities, "participating_entities")
    _strings(chain.participating_relationships, "participating_relationships")
    _strings(chain.mitre_techniques, "mitre_techniques")
    _strings(chain.recommendations, "recommendations")
    if not isinstance(chain.steps, tuple) or not all(
        isinstance(step, AttackStep) for step in chain.steps
    ):
        raise AttackChainSchemaError("AttackChain.steps must be tuple[AttackStep]")
    if not isinstance(chain.timeline, tuple) or not all(
        isinstance(item, Mapping) for item in chain.timeline
    ):
        raise AttackChainSchemaError("AttackChain.timeline must be tuple[Mapping]")
    if not isinstance(chain.metadata, Mapping):
        raise AttackChainSchemaError("AttackChain.metadata must be a mapping")
    try:
        AttackChainValidator().validate(chain)
    except AttackChainValidationError as error:
        raise AttackChainSchemaError(str(error)) from error


def validate_attack_template(template: AttackTemplate) -> None:
    """Validate an AttackTemplate without mutating it."""
    if not isinstance(template, AttackTemplate):
        raise AttackChainSchemaError("template must be an AttackTemplate")
    for field_name in ("id", "name", "description", "entry_point_type"):
        _string(getattr(template, field_name), f"AttackTemplate.{field_name}")
    _strings(template.mitre_chain, "AttackTemplate.mitre_chain")
    _strings(template.required_entities, "AttackTemplate.required_entities")
    _strings(template.required_findings, "AttackTemplate.required_findings")
    _strings(template.tags, "AttackTemplate.tags")
    if not isinstance(template.confidence_base, int | float):
        raise AttackChainSchemaError("AttackTemplate.confidence_base must be numeric")
    if not isinstance(template.severity, Severity):
        raise AttackChainSchemaError("AttackTemplate.severity must be a Severity enum")


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


def _string(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise AttackChainSchemaError(f"{field_name} must be a non-empty string")


class AttackChainSchema:
    """Class facade matching other THRAGG schema helpers."""

    validate_chain = staticmethod(validate_attack_chain)
    validate_template = staticmethod(validate_attack_template)
    is_valid_chain = staticmethod(is_valid_attack_chain)
