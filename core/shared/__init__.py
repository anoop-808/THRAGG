"""Shared package public API."""

from importlib import import_module
from typing import Any

_EXPORTS = {
    "Confidence": ".constants",
    "DEFAULT_REPORT_OUTPUT_DIR": ".configuration",
    "ErrorSeverity": ".errors",
    "ExportError": ".errors",
    "EntityType": ".constants",
    "BUILD_VERSION": ".version",
    "FRAMEWORK_VERSION": ".version",
    "FrameworkError": ".errors",
    "MODULE_CONTRACT_KEYS": ".configuration",
    "PriorityRanker": ".priority_ranker",
    "PIPELINE_VERSION": ".version",
    "REPORT_VERSION": ".version",
    "ReportValidationError": ".errors",
    "ReportingError": ".errors",
    "SCHEMA_VERSION": ".version",
    "API_VERSION": ".version",
    "Severity": ".constants",
    "TemplateError": ".errors",
    "ThraggError": ".errors",
    "TraceabilityMap": ".traceability_map",
    "coerce_error": ".errors",
    "get_logger": ".logging",
    "logged_operation": ".logging",
    "stable_sha_id": ".stable_id",
}

__all__ = sorted(_EXPORTS)


def __getattr__(name: str) -> Any:
    """Load shared symbols lazily to avoid package import cycles."""
    if name not in _EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(_EXPORTS[name], __name__), name)
    globals()[name] = value
    return value
