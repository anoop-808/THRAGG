"""Structured framework error objects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

__all__ = [
    "ErrorSeverity",
    "ExportError",
    "FrameworkError",
    "ReportValidationError",
    "ReportingError",
    "TemplateError",
    "ThraggError",
    "coerce_error",
]


class ThraggError(Exception):
    """Base exception for THRAGG domain failures."""


class ReportingError(ThraggError):
    """Base exception for Reporting Layer failures."""


class ReportValidationError(ReportingError):
    """Raised when a ReportModel fails reporting validation."""

    def __init__(self, rule: int | str, message: str) -> None:
        self.rule = rule
        self.message = message
        super().__init__(f"[Rule {rule}] {message}")


class TemplateError(ReportValidationError):
    """Raised for report template failures."""


class ExportError(ReportingError):
    """Raised when an exporter cannot write rendered content."""


class ErrorSeverity(str, Enum):
    """Framework error severity labels."""

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class FrameworkError:
    """Structured error that remains string-compatible."""

    code: str
    message: str
    layer: str
    recoverable: bool
    severity: ErrorSeverity = ErrorSeverity.ERROR
    source: str = "thragg"

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "layer": self.layer,
            "recoverable": self.recoverable,
            "severity": self.severity.value,
            "source": self.source,
        }

    def __str__(self) -> str:
        return self.message


def coerce_error(error: object, *, layer: str, source: str) -> FrameworkError:
    """Return a FrameworkError for mixed legacy error values."""
    if isinstance(error, FrameworkError):
        return error
    return FrameworkError(
        code="THRAGG-LEGACY-ERROR",
        message=str(error),
        layer=layer,
        recoverable=True,
        severity=(
            ErrorSeverity.WARNING
            if str(error).strip().upper().startswith("WARNING:")
            else ErrorSeverity.ERROR
        ),
        source=source,
    )
