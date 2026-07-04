"""
core.relationship_fact
======================

Shared RelationshipFact model for THRAGG.

A RelationshipFact is the atomic unit of relationship knowledge.
It represents one evidence-backed, directional connection between two
ResolvedEntities and answers exactly four questions:

  WHO?           source_entity_id  →  target_entity_id
  HOW?           relationship_type  (RelationshipType enum — never free text)
  WHY?           supporting_findings, supporting_evidence, observed_at
  WHO SAID SO?   source_module, source_rule

Design constraints
------------------
- RelationshipFacts are **immutable**.  ``frozen=True`` prevents field
  reassignment.  ``__post_init__`` defensively copies all mutable
  inputs so callers cannot mutate a fact after construction.
- Never instantiate RelationshipFact directly.  Use RelationshipBuilder.
- supporting_findings is stored as a tuple (immutable by value).
- supporting_evidence is stored as a shallow copy of the caller's dict.
- Every relationship preserves full evidence traceability.

Stability contract
------------------
This data model is frozen for Milestone 4.  Future fields must be
added in dedicated milestones without removing existing fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .finding import Confidence, EntityType
from .stable_id import stable_sha_id

__all__ = ["RelationshipType", "RelationshipFact", "stable_relationship_fact_id"]


# ---------------------------------------------------------------------------
# Relationship type enumeration
# ---------------------------------------------------------------------------

class RelationshipType(str, Enum):
    """
    Centralized relationship vocabulary.

    Modules MUST use this enum.  Arbitrary relationship strings are
    rejected by RelationshipValidator and never enter the KnowledgeBase.

    Defined types
    -------------
    EXPOSES        – HOST exposes a SERVICE or APPLICATION to the network.
    RUNS           – HOST/CONTAINER executes a SERVICE or APPLICATION.
    HOSTED_IN      – Asset is physically or logically deployed inside another.
    USES           – Component depends on a resource (DATABASE, STORAGE, SERVICE).
    AUTHENTICATED_TO – Principal authenticated to a target asset.
    MEMBER_OF      – Principal or IDENTITY belongs to an IDENTITY group.
    ATTACHED_TO    – Physical or logical attachment (storage volume, NIC).
    CONNECTED_TO   – Network-level connection between two assets.
    OWNS           – Ownership or administrative control relationship.
    RESOLVES_TO    – DNS or name-resolution relationship.
    """

    EXPOSES          = "EXPOSES"
    RUNS             = "RUNS"
    HOSTED_IN        = "HOSTED_IN"
    USES             = "USES"
    AUTHENTICATED_TO = "AUTHENTICATED_TO"
    MEMBER_OF        = "MEMBER_OF"
    ATTACHED_TO      = "ATTACHED_TO"
    CONNECTED_TO     = "CONNECTED_TO"
    OWNS             = "OWNS"
    RESOLVES_TO      = "RESOLVES_TO"


# ---------------------------------------------------------------------------
# Stable ID generation
# ---------------------------------------------------------------------------

def stable_relationship_fact_id(
    source_entity_id: str,
    target_entity_id: str,
    relationship_type: RelationshipType,
    source_module: str,
    source_rule: str,
) -> str:
    """
    Generate a deterministic RelationshipFact identifier.

    ID is derived from the five inputs that uniquely identify one
    evidence-backed relationship assertion:

        SHA-256("<source>|<target>|<type>|<module>|<rule>")[:16]

    prefixed with ``"rel-"``, e.g. ``"rel-3f1a9c2d84b67e01"``.

    Same inputs → same ID across runs and processes.
    Different source_rule or different module → different ID, so a
    single network relationship observed by both nmap and logs produces
    two distinct, independently traceable facts.
    """
    return stable_sha_id(
        "rel",
        source_entity_id,
        target_entity_id,
        relationship_type.value,
        source_module,
        source_rule,
    )


# ---------------------------------------------------------------------------
# RelationshipFact dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RelationshipFact:
    """
    One immutable, evidence-backed relationship between two ResolvedEntities.

    Created **only** by :class:`~core.relationship_builder.RelationshipBuilder`.
    Never instantiate this class directly.

    Immutability
    ------------
    ``frozen=True`` prevents field reassignment after construction.
    ``__post_init__`` converts all mutable caller inputs into defensive
    copies, so callers cannot inadvertently mutate a fact after passing
    it to the builder.

    Fields
    ------
    id : str
        Deterministic, stable identifier.  See :func:`stable_relationship_fact_id`.
    source_entity_id : str
        ID of the origin ResolvedEntity (the "WHO" source).
    source_entity_type : EntityType
        EntityType of the source, captured at construction time so the
        fact is self-describing without requiring a resolver lookup.
    target_entity_id : str
        ID of the destination ResolvedEntity (the "WHO" target).
    target_entity_type : EntityType
        EntityType of the target, captured at construction time.
    relationship_type : RelationshipType
        The "HOW" — the nature of the connection.
    source_module : str
        Module that produced this fact (the "WHO SAID SO").
    source_rule : str
        Rule within the module that triggered this fact.
    confidence : Confidence
        Certainty that this relationship is real.
    supporting_findings : tuple[str, ...]
        IDs of the Finding objects that provide the "WHY".
        Stored as a tuple (immutable by value).
    supporting_evidence : dict[str, Any]
        Raw supporting data from the originating evidence.
        The reference is frozen; treat the contents as read-only.
    observed_at : str | None
        ISO 8601 timestamp of the observation, or None.
    """

    # ── Required fields ────────────────────────────────────────────────────
    id:                  str
    source_entity_id:    str
    source_entity_type:  EntityType
    target_entity_id:    str
    target_entity_type:  EntityType
    relationship_type:   RelationshipType
    source_module:       str
    source_rule:         str
    confidence:          Confidence

    # ── Evidence traceability fields ───────────────────────────────────────
    supporting_findings: tuple[str, ...] = field(default_factory=tuple)
    supporting_evidence: dict[str, Any]  = field(default_factory=dict)
    observed_at:         str | None      = None

    def __post_init__(self) -> None:
        """Defensively copy all mutable inputs to enforce immutability semantics."""
        # tuple() accepts any iterable — callers may pass a list
        object.__setattr__(
            self, "supporting_findings", tuple(self.supporting_findings)
        )
        # Shallow-copy the dict so caller mutations don't affect this fact
        object.__setattr__(
            self, "supporting_evidence", dict(self.supporting_evidence)
        )

    # ── Serialization ──────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize to a plain dictionary suitable for JSON output.

        Enum members are emitted as their string ``.value``.
        ``supporting_findings`` is returned as a list for JSON
        compatibility (tuples serialize as arrays in JSON anyway, but
        an explicit list is more readable for downstream consumers).
        """
        return {
            "id":                  self.id,
            "source_entity_id":    self.source_entity_id,
            "source_entity_type":  self.source_entity_type.value,
            "target_entity_id":    self.target_entity_id,
            "target_entity_type":  self.target_entity_type.value,
            "relationship_type":   self.relationship_type.value,
            "source_module":       self.source_module,
            "source_rule":         self.source_rule,
            "confidence":          self.confidence.value,
            "supporting_findings": list(self.supporting_findings),
            "supporting_evidence": dict(self.supporting_evidence),
            "observed_at":         self.observed_at,
        }
