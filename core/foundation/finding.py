# ─────────────────────────────────────────────────────────────────────────────
# core/finding.py
# ─────────────────────────────────────────────────────────────────────────────
"""
core.finding
============

Shared Finding model and enumerations for THRAGG.

This module is the **single source of truth** for the finding schema.
Do not duplicate this schema in individual modules or test files.

Design constraints
------------------
- Finding is a plain data container. No validation logic lives here.
- All validation lives in finding_schema.py (testable in isolation).
- All construction lives in finding_builder.py (single creation path).
- Modules never instantiate Finding directly; they call build_finding().

Stability contract
------------------
The public surface (Finding fields + enum values) is frozen for
Milestone 1. Future fields (risk_score, entity_type, etc.) will be
added in dedicated milestones without removing existing fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """
    Ordered severity levels.

    String inheritance lets enum members compare and serialize as plain
    strings, which keeps JSON output and logging readable without extra
    conversion steps.
    """

    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    """
    Confidence in a finding's accuracy.

    LOW      – heuristic or indirect signal only.
    MEDIUM   – corroborated by multiple signals.
    HIGH     – deterministic or directly confirmed.
    """

    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"


class EntityType(str, Enum):
    """
    The class of asset a finding refers to.

    Allows downstream consumers (dashboards, correlation engines) to
    group, filter, and route findings without parsing free-text asset
    names.

    Values are uppercase strings so they serialize identically whether
    the enum or its .value is used.
    """

    HOST             = "HOST"
    USER             = "USER"
    SERVICE          = "SERVICE"
    APPLICATION      = "APPLICATION"
    IP_ADDRESS       = "IP_ADDRESS"
    PORT             = "PORT"
    CONTAINER        = "CONTAINER"
    NETWORK          = "NETWORK"
    STORAGE          = "STORAGE"
    DATABASE         = "DATABASE"
    CLOUD_RESOURCE   = "CLOUD_RESOURCE"
    IDENTITY         = "IDENTITY"
    PROCESS          = "PROCESS"
    FILE             = "FILE"
    REGISTRY_KEY     = "REGISTRY_KEY"
    DOMAIN           = "DOMAIN"
    CERTIFICATE      = "CERTIFICATE"
    UNKNOWN          = "UNKNOWN"


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """
    One standardized security finding.

    Produced **only** by :func:`~core.finding_builder.build_finding`.
    Modules must never construct this class directly so that validation
    and defaults remain in one place.

    Fields
    ------
    id : str
        Stable, deterministic identifier.  Format is caller-defined but
        must be non-empty and unique within a module run.
        See :mod:`core.finding_builder` for the recommended scheme.
    title : str
        Short, human-readable summary (≤ 120 chars recommended).
    description : str
        Full narrative description of the finding.
    severity : Severity
        Impact classification.
    confidence : Confidence
        Certainty that the finding is a true positive.
    category : str
        Security domain label (e.g. ``"Authentication"``, ``"Network Exposure"``).
    type : str
        Machine-readable event kind (e.g. ``"FAILED_LOGIN"``, ``"SSH_EXPOSED"``).
        Use SCREAMING_SNAKE_CASE by convention.
    entity_type : EntityType
        Class of asset the finding concerns.  Defaults to UNKNOWN when
        the caller cannot determine the asset class.
    asset : str | None
        Identifier of the affected asset (IP, hostname, username, ARN…).
        ``None`` when the finding is not tied to a specific asset.
    observed_at : str | None
        ISO 8601 timestamp of the observation.  ``None`` when unavailable.
    source_module : str
        Module that produced the finding (e.g. ``"nmap"``, ``"logs"``).
    source_rule : str
        Rule identifier within the module (e.g. ``"NMAP-SSH-EXPOSED-001"``).
    mitre : list[str]
        MITRE ATT&CK technique IDs (e.g. ``["T1021.004"]``).  Empty list
        when not applicable.
    tags : list[str]
        Arbitrary labels for filtering/grouping.
    evidence : dict[str, Any]
        Raw supporting data.  Schema is rule-defined.
    recommendation : str | None
        Remediation guidance for the analyst.
    """

    # ── Required fields ────────────────────────────────────────────────────
    id:            str
    title:         str
    description:   str
    severity:      Severity
    confidence:    Confidence
    category:      str
    type:          str
    source_module: str
    source_rule:   str

    # ── Optional scalar fields ─────────────────────────────────────────────
    entity_type:    EntityType      = EntityType.UNKNOWN
    asset:          str | None      = None
    observed_at:    str | None      = None
    recommendation: str | None      = None

    # ── Optional collection fields ─────────────────────────────────────────
    mitre:    list[str]       = field(default_factory=list)
    tags:     list[str]       = field(default_factory=list)
    evidence: dict[str, Any]  = field(default_factory=dict)

    # ── Serialization ──────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize to a plain dictionary suitable for JSON output.

        Enum members are emitted as their string ``.value`` so that
        callers never need to import the enum classes to read output.
        All mutable collections are shallow-copied to prevent accidental
        mutation of the Finding's internal state.
        """
        return {
            "id":             self.id,
            "title":          self.title,
            "description":    self.description,
            "severity":       self.severity.value,
            "confidence":     self.confidence.value,
            "category":       self.category,
            "type":           self.type,
            "entity_type":    self.entity_type.value,
            "asset":          self.asset,
            "observed_at":    self.observed_at,
            "source_module":  self.source_module,
            "source_rule":    self.source_rule,
            "mitre":          list(self.mitre),
            "tags":           list(self.tags),
            "evidence":       dict(self.evidence),
            "recommendation": self.recommendation,
        }
