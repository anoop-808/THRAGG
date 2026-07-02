# ─────────────────────────────────────────────────────────────────────────────
# core/finding_schema.py
# ─────────────────────────────────────────────────────────────────────────────
"""
core.finding_schema
===================

Validation for :class:`~core.finding.Finding` objects.

Kept deliberately separate from ``finding.py`` so that:

- The model stays a pure data container with no embedded logic.
- Validation rules are testable in complete isolation.
- Callers can choose between raising (:func:`validate_finding`) and
  boolean (:func:`is_valid_finding`) variants depending on context.

Validation philosophy
---------------------
- :func:`validate_finding` raises on the **first** violation it finds.
  This is intentional: one clear error message is more actionable than
  a flood of cascading errors from a single bad field.
- This module never mutates the Finding it receives.
- Enum coercion (string → enum) is the builder's responsibility, not
  the validator's.
"""

from __future__ import annotations

from typing import Any

from .finding import Confidence, EntityType, Finding, Severity

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Fields that must be non-empty strings in every valid Finding.
REQUIRED_STRING_FIELDS: tuple[str, ...] = (
    "id",
    "title",
    "description",
    "category",
    "type",
    "source_module",
    "source_rule",
)

#: Valid EntityType values expressed as a sorted tuple for error messages.
VALID_ENTITY_TYPES: tuple[str, ...] = tuple(
    sorted(e.value for e in EntityType)
)

#: Valid Severity values expressed as a sorted tuple for error messages.
VALID_SEVERITIES: tuple[str, ...] = tuple(
    sorted(e.value for e in Severity)
)

#: Valid Confidence values expressed as a sorted tuple for error messages.
VALID_CONFIDENCES: tuple[str, ...] = tuple(
    sorted(e.value for e in Confidence)
)


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class FindingValidationError(ValueError):
    """
    Raised when a :class:`~core.finding.Finding` fails schema validation.

    Carries a human-readable message describing exactly which field
    failed and what was expected vs. received.
    """


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------

def validate_finding(finding: Finding) -> None:
    """
    Validate a :class:`~core.finding.Finding` instance against the schema.

    Raises :class:`FindingValidationError` on the first violation found.
    Callers decide whether to skip or propagate -- this function only
    inspects, never mutates.

    Parameters
    ----------
    finding:
        The Finding instance to validate.

    Raises
    ------
    FindingValidationError
        If any field violates the schema.
    """
    # ── Required non-empty string fields ──────────────────────────────────
    for field_name in REQUIRED_STRING_FIELDS:
        value = getattr(finding, field_name)
        if not isinstance(value, str) or not value.strip():
            raise FindingValidationError(
                f"Finding.{field_name} must be a non-empty string.\n"
                f"  Received: {value!r}"
            )

    # ── Enum fields ────────────────────────────────────────────────────────
    if not isinstance(finding.severity, Severity):
        raise FindingValidationError(
            f"Finding.severity must be a Severity enum member.\n"
            f"  Expected one of: {', '.join(VALID_SEVERITIES)}\n"
            f"  Received: {finding.severity!r}"
        )

    if not isinstance(finding.confidence, Confidence):
        raise FindingValidationError(
            f"Finding.confidence must be a Confidence enum member.\n"
            f"  Expected one of: {', '.join(VALID_CONFIDENCES)}\n"
            f"  Received: {finding.confidence!r}"
        )

    if not isinstance(finding.entity_type, EntityType):
        raise FindingValidationError(
            f"Finding.entity_type must be an EntityType enum member.\n"
            f"  Expected one of: {', '.join(VALID_ENTITY_TYPES)}\n"
            f"  Received: {finding.entity_type!r}"
        )

    # ── Optional string fields (None is allowed, but not other types) ──────
    if finding.asset is not None and not isinstance(finding.asset, str):
        raise FindingValidationError(
            f"Finding.asset must be a str or None.\n"
            f"  Received: {finding.asset!r} ({type(finding.asset).__name__})"
        )

    if finding.observed_at is not None and not isinstance(finding.observed_at, str):
        raise FindingValidationError(
            f"Finding.observed_at must be a str or None.\n"
            f"  Received: {finding.observed_at!r} ({type(finding.observed_at).__name__})"
        )

    if finding.recommendation is not None and not isinstance(
        finding.recommendation, str
    ):
        raise FindingValidationError(
            f"Finding.recommendation must be a str or None.\n"
            f"  Received: {finding.recommendation!r} ({type(finding.recommendation).__name__})"
        )

    # ── Optional whitespace-only string checks ─────────────────────────────
    # asset and observed_at may be None but must not be blank strings.
    if isinstance(finding.asset, str) and not finding.asset.strip():
        raise FindingValidationError(
            "Finding.asset must not be an empty or whitespace-only string.\n"
            "  Use None to indicate no asset."
        )

    if isinstance(finding.observed_at, str) and not finding.observed_at.strip():
        raise FindingValidationError(
            "Finding.observed_at must not be an empty or whitespace-only string.\n"
            "  Use None to indicate no observation timestamp."
        )

    # ── Collection fields ──────────────────────────────────────────────────
    if not isinstance(finding.mitre, list) or not all(
        isinstance(m, str) for m in finding.mitre
    ):
        raise FindingValidationError(
            "Finding.mitre must be a list[str].\n"
            f"  Received: {finding.mitre!r}"
        )

    if not isinstance(finding.tags, list) or not all(
        isinstance(t, str) for t in finding.tags
    ):
        raise FindingValidationError(
            "Finding.tags must be a list[str].\n"
            f"  Received: {finding.tags!r}"
        )

    if not isinstance(finding.evidence, dict):
        raise FindingValidationError(
            "Finding.evidence must be a dict.\n"
            f"  Received: {finding.evidence!r} ({type(finding.evidence).__name__})"
        )


def is_valid_finding(finding: Finding) -> bool:
    """
    Non-raising convenience wrapper around :func:`validate_finding`.

    Returns ``True`` when the Finding is valid, ``False`` otherwise.
    Intended for callers that want to skip-and-log rather than raise.

    Parameters
    ----------
    finding:
        The Finding instance to check.

    Returns
    -------
    bool
        ``True`` if valid, ``False`` on any validation failure.
    """
    try:
        validate_finding(finding)
        return True
    except FindingValidationError:
        return False
