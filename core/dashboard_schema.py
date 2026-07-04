"""
core.dashboard_schema
=====================

Structural validation for Milestone 10 dashboard contracts.
"""

from __future__ import annotations

from datetime import datetime

from .dashboard_bundle import DashboardBundle
from .dashboard_view import DashboardView

__all__ = ["DashboardSchema", "DashboardSchemaError"]


class DashboardSchemaError(ValueError):
    """Raised when an M10 dashboard contract fails validation."""


class DashboardSchema:
    """Validator for M10 dashboard contracts."""

    @staticmethod
    def validate_bundle(bundle: DashboardBundle) -> None:
        """Validate a DashboardBundle without mutating it."""
        if not isinstance(bundle, DashboardBundle):
            raise DashboardSchemaError("bundle must be a DashboardBundle")
        _id(bundle.id, "DashboardBundle.id")
        _html_path(bundle.html_file, "DashboardBundle.html_file")
        _snapshot(bundle.data_snapshot, "DashboardBundle.data_snapshot")
        _timestamp(bundle.generated_at, "DashboardBundle.generated_at")
        _non_empty_string(bundle.engine_version, "DashboardBundle.engine_version")

    @staticmethod
    def is_valid_bundle(bundle: DashboardBundle) -> bool:
        """Return True when a bundle passes schema validation."""
        try:
            DashboardSchema.validate_bundle(bundle)
            return True
        except DashboardSchemaError:
            return False

    @staticmethod
    def validate_view(view: DashboardView) -> None:
        """Validate one DashboardView value."""
        if not isinstance(view, DashboardView):
            raise DashboardSchemaError("view must be a DashboardView")

    @staticmethod
    def validate_views(views: tuple[DashboardView, ...]) -> None:
        """Validate tuple-backed dashboard views."""
        if not isinstance(views, tuple):
            raise DashboardSchemaError("views must be a tuple")
        for view in views:
            DashboardSchema.validate_view(view)


def _id(value: object, field_name: str) -> None:
    _non_empty_string(value, field_name)
    if any(character.isspace() for character in value):
        raise DashboardSchemaError(f"{field_name} must not contain whitespace")


def _html_path(value: object, field_name: str) -> None:
    _non_empty_string(value, field_name)
    if not value.endswith(".html"):
        raise DashboardSchemaError(f"{field_name} must end with .html")


def _snapshot(value: object, field_name: str) -> None:
    if not isinstance(value, tuple):
        raise DashboardSchemaError(f"{field_name} must be a tuple")
    for item in value:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(part, str) and part.strip() for part in item)
        ):
            raise DashboardSchemaError(f"{field_name} entries must be tuple[str, str]")


def _timestamp(value: object, field_name: str) -> None:
    _non_empty_string(value, field_name)
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise DashboardSchemaError(f"{field_name} must be an ISO timestamp") from error


def _non_empty_string(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DashboardSchemaError(f"{field_name} must be a non-empty string")
