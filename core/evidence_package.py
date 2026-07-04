"""
core.evidence_package
=====================

Milestone 9 evidence package contracts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .stable_id import stable_sha_id

__all__ = [
    "EvidencePackageManifest",
    "EvidencePackage",
    "stable_evidence_package_id",
]


def stable_evidence_package_id(
    package_id: str,
    output_directory: str,
    files_written: tuple[str, ...],
    generated_at: str,
) -> str:
    """Return a deterministic EvidencePackage id."""
    return stable_sha_id(
        "pkg",
        package_id,
        output_directory,
        generated_at,
        *files_written,
    )


@dataclass(frozen=True)
class EvidencePackageManifest:
    """Immutable manifest for a published evidence package."""

    package_id: str
    generated_at: str
    engine_version: str
    thragg_version: str
    files: tuple[str, ...]
    snapshot_summary: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        """Defensively copy caller-owned iterables."""
        object.__setattr__(self, "files", tuple(self.files))
        object.__setattr__(
            self,
            "snapshot_summary",
            tuple((key, value) for key, value in self.snapshot_summary),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain package manifest data."""
        return {
            "package_id": self.package_id,
            "generated_at": self.generated_at,
            "engine_version": self.engine_version,
            "thragg_version": self.thragg_version,
            "files": list(self.files),
            "snapshot_summary": [list(item) for item in self.snapshot_summary],
        }


@dataclass(frozen=True)
class EvidencePackage:
    """Immutable evidence package publication record."""

    id: str
    manifest: EvidencePackageManifest
    output_directory: str
    files_written: tuple[str, ...]
    generated_at: str
    # Overall THRAGG release; distinct from engine and snapshot schema versions.
    framework_version: str = "1.0"

    def __post_init__(self) -> None:
        """Defensively copy caller-owned iterables."""
        object.__setattr__(self, "files_written", tuple(self.files_written))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain package data."""
        return {
            "id": self.id,
            "manifest": self.manifest.to_dict(),
            "output_directory": self.output_directory,
            "files_written": list(self.files_written),
            "generated_at": self.generated_at,
            "framework_version": self.framework_version,
        }
