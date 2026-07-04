"""
core.relationship_schema
========================

Structural validation for :class:`~core.relationship_fact.RelationshipFact`
objects.

Responsibility boundary
-----------------------
This module validates **structure** only:

  ✅  Required string fields are non-empty.
  ✅  Enum fields hold the correct enum types.
  ✅  source_entity_id ≠ target_entity_id (self-reference prevention).
  ✅  supporting_findings contains only non-blank strings.
  ✅  supporting_evidence is a dict with string keys.
  ✅  observed_at is a str or None (not any other type).

  ❌  Does NOT validate whether the relationship type is meaningful
      for the given entity types.  That is RelationshipValidator's job.

Design mirrors finding_schema.py:
- ``validate_relationship_fact`` raises on the first violation.
- ``is_valid_relationship_fact`` returns bool (non-raising wrapper).
- No mutation of the fact under any circumstances.
"""

from __future__ import annotations

from .finding import Confidence, EntityType
from .core_relationship_fact import RelationshipFact, RelationshipType

__all__ = [
    "RelationshipSchemaError",
    "validate_relationship_fact",
    "is_valid_relationship_fact",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Fields that must be non-empty strings in every valid RelationshipFact.
_REQUIRED_STRING_FIELDS: tuple[str, ...] = (
    "id",
    "source_entity_id",
    "target_entity_id",
    "source_module",
    "source_rule",
)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class RelationshipSchemaError(ValueError):
    """
    Raised when a :class:`~core.relationship_fact.RelationshipFact` fails
    structural schema validation.
    """


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_relationship_fact(fact: RelationshipFact) -> None:
    """
    Validate the structural integrity of a RelationshipFact.

    Raises :class:`RelationshipSchemaError` on the **first** violation.
    Never mutates the fact.

    Parameters
    ----------
    fact:
        The RelationshipFact instance to validate.

    Raises
    ------
    RelationshipSchemaError
        If any structural constraint is violated.
    """
    # ── Required non-empty string fields ──────────────────────────────────
    for field_name in _REQUIRED_STRING_FIELDS:
        value = getattr(fact, field_name)
        if not isinstance(value, str) or not value.strip():
            raise RelationshipSchemaError(
                f"RelationshipFact.{field_name} must be a non-empty string.\n"
                f"  Received: {value!r}"
            )

    # ── Self-reference prevention ──────────────────────────────────────────
    if fact.source_entity_id == fact.target_entity_id:
        raise RelationshipSchemaError(
            "RelationshipFact.source_entity_id must differ from target_entity_id.\n"
            f"  Both are: {fact.source_entity_id!r}"
        )

    # ── Enum fields ────────────────────────────────────────────────────────
    if not isinstance(fact.relationship_type, RelationshipType):
        raise RelationshipSchemaError(
            "RelationshipFact.relationship_type must be a RelationshipType enum.\n"
            f"  Received: {fact.relationship_type!r}"
        )

    if not isinstance(fact.source_entity_type, EntityType):
        raise RelationshipSchemaError(
            "RelationshipFact.source_entity_type must be an EntityType enum.\n"
            f"  Received: {fact.source_entity_type!r}"
        )

    if not isinstance(fact.target_entity_type, EntityType):
        raise RelationshipSchemaError(
            "RelationshipFact.target_entity_type must be an EntityType enum.\n"
            f"  Received: {fact.target_entity_type!r}"
        )

    if not isinstance(fact.confidence, Confidence):
        raise RelationshipSchemaError(
            "RelationshipFact.confidence must be a Confidence enum.\n"
            f"  Received: {fact.confidence!r}"
        )

    # ── supporting_findings ────────────────────────────────────────────────
    if not isinstance(fact.supporting_findings, (tuple, list)) or not all(
        isinstance(f, str) for f in fact.supporting_findings
    ):
        raise RelationshipSchemaError(
            "RelationshipFact.supporting_findings must be a sequence of strings.\n"
            f"  Received: {fact.supporting_findings!r}"
        )

    for idx, finding_id in enumerate(fact.supporting_findings):
        if not finding_id.strip():
            raise RelationshipSchemaError(
                f"RelationshipFact.supporting_findings[{idx}] must not be blank.\n"
                f"  Received: {finding_id!r}"
            )

    # ── supporting_evidence ────────────────────────────────────────────────
    if not isinstance(fact.supporting_evidence, dict):
        raise RelationshipSchemaError(
            "RelationshipFact.supporting_evidence must be a dict.\n"
            f"  Received: {fact.supporting_evidence!r}"
        )

    if not all(isinstance(k, str) for k in fact.supporting_evidence):
        raise RelationshipSchemaError(
            "RelationshipFact.supporting_evidence keys must all be strings."
        )

    # ── observed_at ────────────────────────────────────────────────────────
    if fact.observed_at is not None:
        if not isinstance(fact.observed_at, str):
            raise RelationshipSchemaError(
                "RelationshipFact.observed_at must be a str or None.\n"
                f"  Received: {fact.observed_at!r} ({type(fact.observed_at).__name__})"
            )
        if not fact.observed_at.strip():
            raise RelationshipSchemaError(
                "RelationshipFact.observed_at must not be an empty or "
                "whitespace-only string.  Use None to indicate no timestamp."
            )


def is_valid_relationship_fact(fact: RelationshipFact) -> bool:
    """
    Non-raising convenience wrapper around :func:`validate_relationship_fact`.

    Returns ``True`` when the fact passes structural validation.
    Intended for callers that prefer skip-and-log over exception handling.
    """
    try:
        validate_relationship_fact(fact)
        return True
    except RelationshipSchemaError:
        return False
