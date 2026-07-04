"""
core.relationship_validator
===========================

Semantic validation for :class:`~core.relationship_fact.RelationshipFact`
objects.

Responsibility boundary
-----------------------
This module validates **meaning** only — specifically, whether the
(source_entity_type, relationship_type, target_entity_type) triple is
a known, allowable combination.

  ✅  HOST   EXPOSES   SERVICE            → valid
  ✅  USER   AUTHENTICATED_TO   HOST      → valid
  ❌  USER   HOSTED_IN   PORT             → invalid (PORT isn't an EntityType)
  ❌  USER   HOSTED_IN   NETWORK          → invalid (users are not hosted in networks)

Structural validation (field types, required fields) is the job of
:mod:`core.relationship_schema`.  Both validators are deliberately
separate so each can be tested and reused independently.

UNKNOWN entity types
--------------------
If either source or target entity type is ``EntityType.UNKNOWN``, the
relationship is permitted but flagged as ``UNKNOWN_ENTITY_TYPE`` in the
validation result.  This ensures that findings with unknown entity types
can still participate in relationship modeling without hard-blocking the
pipeline.

Adding new combinations
-----------------------
Add tuples to ``VALID_COMBINATIONS``.  No other code change required.
The validator is purely data-driven.
"""

from __future__ import annotations

from .finding import EntityType
from .core_relationship_fact import RelationshipFact, RelationshipType
from .core_relationship_schema import (
    RelationshipSchemaError,
    validate_relationship_fact,
)

__all__ = [
    "VALID_COMBINATIONS",
    "InvalidRelationshipCombination",
    "RelationshipValidator",
]

# ---------------------------------------------------------------------------
# Allowed (source_type, relationship_type, target_type) triples
# ---------------------------------------------------------------------------
#
# Each triple asserts: "an entity of source_type CAN have a
# relationship_type relationship to an entity of target_type."
#
# This is the single authoritative list.  Modules must not add their
# own combination rules.

VALID_COMBINATIONS: frozenset[
    tuple[EntityType, RelationshipType, EntityType]
] = frozenset(
    {
        # ── EXPOSES: something exposes a network-accessible asset ──────────
        (EntityType.HOST,        RelationshipType.EXPOSES, EntityType.SERVICE),
        (EntityType.HOST,        RelationshipType.EXPOSES, EntityType.APPLICATION),
        (EntityType.APPLICATION, RelationshipType.EXPOSES, EntityType.SERVICE),
        (EntityType.CONTAINER,   RelationshipType.EXPOSES, EntityType.SERVICE),
        (EntityType.CONTAINER,   RelationshipType.EXPOSES, EntityType.APPLICATION),

        # ── RUNS: something executes another asset ─────────────────────────
        (EntityType.HOST,        RelationshipType.RUNS, EntityType.SERVICE),
        (EntityType.HOST,        RelationshipType.RUNS, EntityType.APPLICATION),
        (EntityType.HOST,        RelationshipType.RUNS, EntityType.CONTAINER),
        (EntityType.CONTAINER,   RelationshipType.RUNS, EntityType.APPLICATION),
        (EntityType.CONTAINER,   RelationshipType.RUNS, EntityType.SERVICE),
        (EntityType.APPLICATION, RelationshipType.RUNS, EntityType.SERVICE),

        # ── HOSTED_IN: something is deployed inside an infrastructure ──────
        (EntityType.HOST,          RelationshipType.HOSTED_IN, EntityType.CLOUD_RESOURCE),
        (EntityType.HOST,          RelationshipType.HOSTED_IN, EntityType.NETWORK),
        (EntityType.APPLICATION,   RelationshipType.HOSTED_IN, EntityType.CLOUD_RESOURCE),
        (EntityType.APPLICATION,   RelationshipType.HOSTED_IN, EntityType.HOST),
        (EntityType.CONTAINER,     RelationshipType.HOSTED_IN, EntityType.HOST),
        (EntityType.CONTAINER,     RelationshipType.HOSTED_IN, EntityType.CLOUD_RESOURCE),
        (EntityType.DATABASE,      RelationshipType.HOSTED_IN, EntityType.CLOUD_RESOURCE),
        (EntityType.DATABASE,      RelationshipType.HOSTED_IN, EntityType.HOST),
        (EntityType.SERVICE,       RelationshipType.HOSTED_IN, EntityType.HOST),
        (EntityType.SERVICE,       RelationshipType.HOSTED_IN, EntityType.CLOUD_RESOURCE),
        (EntityType.STORAGE,       RelationshipType.HOSTED_IN, EntityType.CLOUD_RESOURCE),

        # ── USES: something depends on a resource ─────────────────────────
        (EntityType.APPLICATION, RelationshipType.USES, EntityType.DATABASE),
        (EntityType.APPLICATION, RelationshipType.USES, EntityType.SERVICE),
        (EntityType.APPLICATION, RelationshipType.USES, EntityType.STORAGE),
        (EntityType.HOST,        RelationshipType.USES, EntityType.DATABASE),
        (EntityType.HOST,        RelationshipType.USES, EntityType.STORAGE),
        (EntityType.HOST,        RelationshipType.USES, EntityType.SERVICE),
        (EntityType.SERVICE,     RelationshipType.USES, EntityType.DATABASE),
        (EntityType.SERVICE,     RelationshipType.USES, EntityType.STORAGE),
        (EntityType.SERVICE,     RelationshipType.USES, EntityType.SERVICE),
        (EntityType.USER,        RelationshipType.USES, EntityType.APPLICATION),
        (EntityType.USER,        RelationshipType.USES, EntityType.SERVICE),

        # ── AUTHENTICATED_TO: a principal authenticates to a target ────────
        (EntityType.USER,     RelationshipType.AUTHENTICATED_TO, EntityType.HOST),
        (EntityType.USER,     RelationshipType.AUTHENTICATED_TO, EntityType.APPLICATION),
        (EntityType.USER,     RelationshipType.AUTHENTICATED_TO, EntityType.SERVICE),
        (EntityType.USER,     RelationshipType.AUTHENTICATED_TO, EntityType.DATABASE),
        (EntityType.IDENTITY, RelationshipType.AUTHENTICATED_TO, EntityType.APPLICATION),
        (EntityType.IDENTITY, RelationshipType.AUTHENTICATED_TO, EntityType.SERVICE),
        (EntityType.IDENTITY, RelationshipType.AUTHENTICATED_TO, EntityType.HOST),

        # ── MEMBER_OF: membership / group relationships ────────────────────
        (EntityType.USER,     RelationshipType.MEMBER_OF, EntityType.IDENTITY),
        (EntityType.IDENTITY, RelationshipType.MEMBER_OF, EntityType.IDENTITY),
        (EntityType.HOST,     RelationshipType.MEMBER_OF, EntityType.NETWORK),
        (EntityType.HOST,     RelationshipType.MEMBER_OF, EntityType.CLOUD_RESOURCE),

        # ── ATTACHED_TO: physical or logical attachment ────────────────────
        (EntityType.HOST,          RelationshipType.ATTACHED_TO, EntityType.STORAGE),
        (EntityType.HOST,          RelationshipType.ATTACHED_TO, EntityType.NETWORK),
        (EntityType.CONTAINER,     RelationshipType.ATTACHED_TO, EntityType.STORAGE),
        (EntityType.CLOUD_RESOURCE, RelationshipType.ATTACHED_TO, EntityType.STORAGE),

        # ── CONNECTED_TO: network-layer connectivity ───────────────────────
        (EntityType.HOST,        RelationshipType.CONNECTED_TO, EntityType.NETWORK),
        (EntityType.HOST,        RelationshipType.CONNECTED_TO, EntityType.HOST),
        (EntityType.NETWORK,     RelationshipType.CONNECTED_TO, EntityType.NETWORK),
        (EntityType.SERVICE,     RelationshipType.CONNECTED_TO, EntityType.HOST),
        (EntityType.SERVICE,     RelationshipType.CONNECTED_TO, EntityType.SERVICE),
        (EntityType.APPLICATION, RelationshipType.CONNECTED_TO, EntityType.SERVICE),
        (EntityType.APPLICATION, RelationshipType.CONNECTED_TO, EntityType.HOST),

        # ── OWNS: ownership or administrative control ──────────────────────
        (EntityType.USER,          RelationshipType.OWNS, EntityType.CLOUD_RESOURCE),
        (EntityType.USER,          RelationshipType.OWNS, EntityType.APPLICATION),
        (EntityType.CLOUD_RESOURCE, RelationshipType.OWNS, EntityType.CLOUD_RESOURCE),
        (EntityType.CLOUD_RESOURCE, RelationshipType.OWNS, EntityType.STORAGE),
        (EntityType.IDENTITY,      RelationshipType.OWNS, EntityType.CLOUD_RESOURCE),

        # ── RESOLVES_TO: DNS or name resolution ───────────────────────────
        (EntityType.SERVICE,     RelationshipType.RESOLVES_TO, EntityType.HOST),
        (EntityType.HOST,        RelationshipType.RESOLVES_TO, EntityType.HOST),
        (EntityType.APPLICATION, RelationshipType.RESOLVES_TO, EntityType.HOST),
    }
)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class InvalidRelationshipCombination(ValueError):
    """
    Raised when a RelationshipFact uses an entity-type + relationship-type
    combination that is not present in :data:`VALID_COMBINATIONS`.
    """


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class RelationshipValidator:
    """
    Validates relationship semantics.

    This class is stateless.  All methods are classmethods — no
    instantiation required.

    Two levels of validation are exposed:

    ``validate_combination``  — only the entity-type triple.
    ``validate``              — structural schema **then** combination.
    """

    @classmethod
    def validate_combination(cls, fact: RelationshipFact) -> None:
        """
        Validate that the entity-type + relationship-type combination is allowed.

        ``EntityType.UNKNOWN`` on either side is permitted but raises
        :class:`InvalidRelationshipCombination` if the fully-typed
        combination is not in :data:`VALID_COMBINATIONS` AND neither
        side is UNKNOWN.  When UNKNOWN is involved the method returns
        normally — callers should treat such facts with caution.

        Raises
        ------
        InvalidRelationshipCombination
            When the triple is not allowed and no UNKNOWN side is present.
        """
        triple = (fact.source_entity_type, fact.relationship_type, fact.target_entity_type)

        # UNKNOWN on either side: allow through but don't whitelist-check
        if (
            fact.source_entity_type is EntityType.UNKNOWN
            or fact.target_entity_type is EntityType.UNKNOWN
        ):
            return

        if triple not in VALID_COMBINATIONS:
            raise InvalidRelationshipCombination(
                f"Relationship type combination is not allowed:\n"
                f"  {fact.source_entity_type.value}"
                f"  {fact.relationship_type.value}"
                f"  {fact.target_entity_type.value}\n"
                f"  source_entity_id: {fact.source_entity_id!r}\n"
                f"  target_entity_id: {fact.target_entity_id!r}"
            )

    @classmethod
    def is_valid_combination(cls, fact: RelationshipFact) -> bool:
        """Non-raising wrapper around :meth:`validate_combination`."""
        try:
            cls.validate_combination(fact)
            return True
        except InvalidRelationshipCombination:
            return False

    @classmethod
    def validate(cls, fact: RelationshipFact) -> None:
        """
        Full validation: structural schema first, then semantic combination.

        Raises
        ------
        RelationshipSchemaError
            On any structural violation.
        InvalidRelationshipCombination
            When the combination is not in :data:`VALID_COMBINATIONS`.
        """
        validate_relationship_fact(fact)
        cls.validate_combination(fact)

    @classmethod
    def is_valid(cls, fact: RelationshipFact) -> bool:
        """Non-raising wrapper around :meth:`validate`."""
        try:
            cls.validate(fact)
            return True
        except (RelationshipSchemaError, InvalidRelationshipCombination):
            return False

    @classmethod
    def has_unknown_entity_type(cls, fact: RelationshipFact) -> bool:
        """
        Return True when either entity type is UNKNOWN.

        Callers may wish to flag or downgrade confidence on these facts
        even though they are not rejected.
        """
        return (
            fact.source_entity_type is EntityType.UNKNOWN
            or fact.target_entity_type is EntityType.UNKNOWN
        )
