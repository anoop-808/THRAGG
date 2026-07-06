"""
core.risk.enums
================

Strongly-typed enums shared across the Risk Engine, replacing magic strings.

RiskLevel used to be defined inline in risk_calculator.py. It now lives
here so scoring_policy.py, risk_calculator.py, and anything else that
needs it can import it without a circular dependency. risk_calculator.py
still re-exports RiskLevel for backward compatibility
(`from .risk_calculator import RiskLevel` keeps working).
"""

from __future__ import annotations

from enum import Enum


class RiskLevel(str, Enum):
    """Deterministic risk level thresholds. Frozen — do not change without review."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskCategory(str, Enum):
    """
    Known primary_category values produced by RiskBuilder._derive_category().

    NOT_LISTED is used as a safe fallback for entity-type-derived categories
    that don't have a dedicated enum member (e.g. a new entity type added
    to an upstream system before this enum is updated) — see
    RiskCategory.from_str().
    """
    MULTI_DOMAIN = "Multi-Domain"
    DOMAIN_CONTROLLER = "DOMAIN_CONTROLLER"
    IDENTITY_PROVIDER = "IDENTITY_PROVIDER"
    DATABASE = "DATABASE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    STORAGE = "STORAGE"
    APPLICATION = "APPLICATION"
    HOST = "HOST"
    SERVICE = "SERVICE"
    NETWORK = "NETWORK"
    CONTAINER = "CONTAINER"
    USER = "USER"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, value: str) -> "RiskCategory":
        """Best-effort coercion. Falls back to UNKNOWN instead of raising,
        so an unrecognized upstream entity type never crashes RiskBuilder."""
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN


class Environment(str, Enum):
    """Known deployment environments for an asset. Drives impact scoring."""
    PROD = "prod"
    STAGING = "staging"
    DEV = "dev"
    TEST = "test"
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: str) -> "Environment":
        normalized = (value or "unknown").lower()
        aliases = {"production": cls.PROD, "development": cls.DEV}
        if normalized in aliases:
            return aliases[normalized]
        try:
            return cls(normalized)
        except ValueError:
            return cls.UNKNOWN
