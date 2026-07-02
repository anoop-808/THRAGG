# ─────────────────────────────────────────────────────────────────────────────
# core/finding_builder.py
# ─────────────────────────────────────────────────────────────────────────────
"""
core.finding_builder
====================

Converts one rule-result dictionary into one validated
:class:`~core.finding.Finding`.

Responsibilities (this module only)
-------------------------------------
✅  Coerce raw strings into typed enum values.
✅  Apply defaults for optional fields.
✅  Generate stable, deterministic finding IDs.
✅  Delegate validation to finding_schema.validate_finding().
✅  Swallow malformed entries (log + return None) so a single bad
    rule result never crashes the whole module run (ADR-001).

Explicitly NOT here
-------------------
❌  Security analysis or detection logic.
❌  Evidence parsing.
❌  Risk scoring (future milestone).
❌  Rule execution.

ID stability contract
---------------------
Finding IDs are built from ``source_module`` + ``source_rule`` +
``asset`` (or ``"no-asset"``) and hashed with SHA-256 (truncated to
16 hex chars).  The same inputs always produce the same ID, which
means:

- IDs survive module restarts.
- Duplicate suppression in downstream systems works without a
  persistent store.
- IDs are safe to store in reports as stable references.

Callers that need a custom ID scheme may pass ``id`` explicitly;
the auto-generation is skipped when ``id`` is provided.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from .finding import Confidence, EntityType, Finding, Severity
from .finding_schema import FindingValidationError, validate_finding

logger = logging.getLogger("thragg.finding_builder")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _coerce_severity(value: Any) -> Severity:
    """
    Convert a raw value to a :class:`~core.finding.Severity` enum member.

    Accepts an existing ``Severity`` instance (pass-through) or any
    value whose ``str()`` representation, uppercased, matches a valid
    member name.

    Raises
    ------
    FindingValidationError
        When the value cannot be mapped to a known Severity.
    """
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).upper())
    except ValueError as exc:
        valid = ", ".join(e.value for e in Severity)
        raise FindingValidationError(
            f"Invalid severity value: {value!r}\n"
            f"  Expected one of: {valid}"
        ) from exc


def _coerce_confidence(value: Any) -> Confidence:
    """
    Convert a raw value to a :class:`~core.finding.Confidence` enum member.

    Same coercion rules as :func:`_coerce_severity`.

    Raises
    ------
    FindingValidationError
        When the value cannot be mapped to a known Confidence.
    """
    if isinstance(value, Confidence):
        return value
    try:
        return Confidence(str(value).upper())
    except ValueError as exc:
        valid = ", ".join(e.value for e in Confidence)
        raise FindingValidationError(
            f"Invalid confidence value: {value!r}\n"
            f"  Expected one of: {valid}"
        ) from exc


def _coerce_entity_type(value: Any) -> EntityType:
    """
    Convert a raw value to an :class:`~core.finding.EntityType` enum member.

    Falls back to ``EntityType.UNKNOWN`` when value is ``None`` or an
    empty string so callers do not need to handle the default case.

    Raises
    ------
    FindingValidationError
        When the value is non-None/non-empty but does not match any
        known EntityType.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return EntityType.UNKNOWN
    if isinstance(value, EntityType):
        return value
    try:
        return EntityType(str(value).upper())
    except ValueError as exc:
        valid = ", ".join(e.value for e in EntityType)
        raise FindingValidationError(
            f"Invalid entity_type value: {value!r}\n"
            f"  Expected one of: {valid}"
        ) from exc


def _generate_id(source_module: str, source_rule: str, asset: str | None) -> str:
    """
    Generate a stable, deterministic finding ID.

    The ID is constructed as::

        SHA-256( "<source_module>|<source_rule>|<asset_or_no-asset>" )[:16]

    This guarantees:

    - Same inputs → same ID (idempotent across runs).
    - Different asset + same rule → different ID.
    - No external state or counters needed.

    Parameters
    ----------
    source_module:
        Module that produced the finding.
    source_rule:
        Rule identifier within the module.
    asset:
        Asset identifier, or ``None``.

    Returns
    -------
    str
        16-character lowercase hex string prefixed with the module name,
        e.g. ``"nmap-3f1a9c2d84b67e01"``.
    """
    asset_part = asset if asset else "no-asset"
    raw        = f"{source_module}|{source_rule}|{asset_part}"
    digest     = hashlib.sha256(raw.encode()).hexdigest()[:16]
    return f"{source_module}-{digest}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_finding(
    *,
    title:         str,
    description:   str,
    severity:      Any,
    confidence:    Any,
    category:      str,
    type:          str,                          # noqa: A002
    source_module: str,
    source_rule:   str,
    id:            str | None      = None,       # noqa: A002
    entity_type:   Any             = None,
    asset:         str | None      = None,
    observed_at:   str | None      = None,
    mitre:         list[str] | None = None,
    tags:          list[str] | None = None,
    evidence:      dict[str, Any] | None = None,
    recommendation: str | None     = None,
) -> Finding | None:
    """
    Build one :class:`~core.finding.Finding` from rule-result fields.

    This is the **only** sanctioned way to create a Finding.  Direct
    instantiation of ``Finding(...)`` bypasses coercion and validation.

    ID generation
    ~~~~~~~~~~~~~
    When ``id`` is omitted (or ``None``), a stable deterministic ID is
    generated from ``source_module``, ``source_rule``, and ``asset``.
    Pass ``id`` explicitly only when a canonical rule-level identifier
    already exists (e.g. ``"NMAP-SSH-EXPOSED-001"``).

    Error handling
    ~~~~~~~~~~~~~~
    Returns ``None`` and logs a ``WARNING`` when the input is malformed.
    This prevents a single bad rule result from crashing the containing
    module run (ADR-001).  The warning includes the module and rule
    names to aid debugging.

    Parameters
    ----------
    title:
        Short, human-readable finding summary.
    description:
        Full narrative description.
    severity:
        ``Severity`` enum member **or** case-insensitive string
        (``"HIGH"``, ``"high"``, etc.).
    confidence:
        ``Confidence`` enum member or case-insensitive string.
    category:
        Security domain label.
    type:
        Machine-readable event kind in SCREAMING_SNAKE_CASE.
    source_module:
        Identifier of the producing module.
    source_rule:
        Identifier of the producing rule.
    id:
        Explicit finding ID.  Auto-generated when omitted.
    entity_type:
        ``EntityType`` enum member, case-insensitive string, or ``None``
        (defaults to ``EntityType.UNKNOWN``).
    asset:
        Affected asset identifier or ``None``.
    observed_at:
        ISO 8601 observation timestamp or ``None``.
    mitre:
        List of MITRE ATT&CK technique IDs.
    tags:
        Arbitrary labels.
    evidence:
        Raw supporting data dict.
    recommendation:
        Remediation guidance or ``None``.

    Returns
    -------
    Finding | None
        A validated Finding, or ``None`` on failure.
    """
    try:
        # Coerce enums before constructing the dataclass so the
        # dataclass fields always hold properly typed values.
        coerced_severity    = _coerce_severity(severity)
        coerced_confidence  = _coerce_confidence(confidence)
        coerced_entity_type = _coerce_entity_type(entity_type)

        # Resolve ID: use explicit id when provided, otherwise generate.
        resolved_id = id if (id is not None and str(id).strip()) else _generate_id(
            source_module, source_rule, asset
        )

        finding = Finding(
            id             = resolved_id,
            title          = title,
            description    = description,
            severity       = coerced_severity,
            confidence     = coerced_confidence,
            category       = category,
            type           = type,
            entity_type    = coerced_entity_type,
            asset          = asset,
            observed_at    = observed_at,
            source_module  = source_module,
            source_rule    = source_rule,
            mitre          = list(mitre)    if mitre    else [],
            tags           = list(tags)     if tags     else [],
            evidence       = dict(evidence) if evidence else {},
            recommendation = recommendation,
        )

        validate_finding(finding)
        return finding

    except FindingValidationError as exc:
        logger.warning(
            "Skipped malformed finding from %s/%s:\n  %s",
            source_module,
            source_rule,
            exc,
        )
        return None


def build_findings_from_rule_results(
    rule_results: list[dict[str, Any]],
    *,
    source_module: str,
) -> list[Finding]:
    """
    Batch-convert a list of rule-result dicts into validated Findings.

    Each dict must contain the keyword arguments accepted by
    :func:`build_finding` (``source_module`` is supplied once here and
    must **not** appear in the individual dicts).

    Malformed entries are skipped and logged, not raised.  This
    guarantees that one bad rule result never prevents the rest of
    the batch from being processed.

    Parameters
    ----------
    rule_results:
        List of rule-result dicts, one per candidate finding.
    source_module:
        Module identifier injected into every Finding.

    Returns
    -------
    list[Finding]
        Only the successfully built and validated Findings.  May be
        shorter than ``rule_results`` when some entries were malformed.
    """
    findings: list[Finding] = []

    for result in rule_results:
        finding = build_finding(source_module=source_module, **result)
        if finding is not None:
            findings.append(finding)

    return findings
