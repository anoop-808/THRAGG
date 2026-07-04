"""
core.evidence_package_schema
============================

Structural validation for Milestone 9 evidence package contracts.
"""

from __future__ import annotations

from .evidence_package import EvidencePackage, EvidencePackageManifest

__all__ = [
    "EvidencePackageSchema",
    "EvidencePackageSchemaError",
]


class EvidencePackageSchemaError(ValueError):
    """Raised when an M9 evidence package contract fails validation."""


class EvidencePackageSchema:
    """Validator for M9 evidence package contracts."""

    @staticmethod
    def validate_manifest(manifest: EvidencePackageManifest) -> None:
        """Validate an EvidencePackageManifest without mutating it."""
        if not isinstance(manifest, EvidencePackageManifest):
            raise EvidencePackageSchemaError(
                "manifest must be an EvidencePackageManifest"
            )
        _id(manifest.package_id, "EvidencePackageManifest.package_id")
        for field_name in ("generated_at", "engine_version", "thragg_version"):
            _non_empty_string(
                getattr(manifest, field_name),
                f"EvidencePackageManifest.{field_name}",
            )
        _strings(manifest.files, "EvidencePackageManifest.files")
        _string_pairs(
            manifest.snapshot_summary,
            "EvidencePackageManifest.snapshot_summary",
        )

    @staticmethod
    def is_valid_manifest(manifest: EvidencePackageManifest) -> bool:
        """Return True when a manifest passes schema validation."""
        try:
            EvidencePackageSchema.validate_manifest(manifest)
            return True
        except EvidencePackageSchemaError:
            return False

    @staticmethod
    def validate_package(package: EvidencePackage) -> None:
        """Validate an EvidencePackage without mutating it."""
        if not isinstance(package, EvidencePackage):
            raise EvidencePackageSchemaError("package must be an EvidencePackage")
        _id(package.id, "EvidencePackage.id")
        if not isinstance(package.manifest, EvidencePackageManifest):
            raise EvidencePackageSchemaError(
                "EvidencePackage.manifest must be EvidencePackageManifest"
            )
        EvidencePackageSchema.validate_manifest(package.manifest)
        _non_empty_string(package.output_directory, "EvidencePackage.output_directory")
        _strings(package.files_written, "EvidencePackage.files_written")
        _non_empty_string(package.generated_at, "EvidencePackage.generated_at")
        _non_empty_string(
            package.framework_version,
            "EvidencePackage.framework_version",
        )

    @staticmethod
    def is_valid_package(package: EvidencePackage) -> bool:
        """Return True when a package passes schema validation."""
        try:
            EvidencePackageSchema.validate_package(package)
            return True
        except EvidencePackageSchemaError:
            return False


def _id(value: object, field_name: str) -> None:
    _non_empty_string(value, field_name)
    if any(character.isspace() for character in value):
        raise EvidencePackageSchemaError(f"{field_name} must not contain whitespace")


def _strings(value: object, field_name: str) -> None:
    if not isinstance(value, tuple) or not all(
        isinstance(item, str) and item.strip() for item in value
    ):
        raise EvidencePackageSchemaError(
            f"{field_name} must be a tuple of non-empty strings"
        )


def _string_pairs(value: object, field_name: str) -> None:
    if not isinstance(value, tuple):
        raise EvidencePackageSchemaError(f"{field_name} must be a tuple")
    for item in value:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not all(isinstance(part, str) and part.strip() for part in item)
        ):
            raise EvidencePackageSchemaError(
                f"{field_name} entries must be tuple[str, str]"
            )


def _non_empty_string(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise EvidencePackageSchemaError(f"{field_name} must be a non-empty string")
