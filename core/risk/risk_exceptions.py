"""
core.risk.exceptions
=====================

Shared THRAGG Risk Engine exception hierarchy.

All domain-specific errors raised anywhere in the Risk layer should
derive from ThraggError so callers can catch broadly (ThraggError) or
narrowly (e.g. PolicyError) as needed.

    ThraggError
    └── RiskError
        ├── ValidationError   (schema / structural violations)
        ├── PolicyError       (policy evaluation / loading failures)
        └── RepositoryError   (storage / dedup failures)

Existing call sites that catch the old concrete exception names
(e.g. RiskSchemaError) keep working because those names are preserved
as subclasses/aliases of the new hierarchy (see risk_schema.py).
"""

from __future__ import annotations


class ThraggError(Exception):
    """Base class for every THRAGG-raised exception."""


class RiskError(ThraggError):
    """Base class for all Risk Engine errors."""


class ValidationError(RiskError):
    """Raised when a RiskAssessment (or component) fails schema validation."""


class PolicyError(RiskError):
    """Raised on policy load or evaluation failures."""


class RepositoryError(RiskError):
    """Raised on RiskRepository storage/dedup failures."""
