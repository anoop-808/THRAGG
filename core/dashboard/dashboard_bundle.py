"""
core.dashboard_bundle
=====================

Milestone 10 dashboard bundle contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..shared.stable_id import stable_sha_id

__all__ = ["DashboardBundle", "stable_dashboard_bundle_id"]


def stable_dashboard_bundle_id(
    html_file: str,
    data_snapshot: tuple[tuple[str, str], ...],
    generated_at: str,
    engine_version: str,
) -> str:
    """Return a deterministic DashboardBundle id."""
    snapshot = "|".join(f"{key}={value}" for key, value in tuple(data_snapshot))
    return stable_sha_id("dash", html_file, snapshot, generated_at, engine_version)


@dataclass(frozen=True)
class DashboardBundle:
    """Immutable dashboard publication contract."""

    id: str
    html_file: str
    data_snapshot: tuple[tuple[str, str], ...]
    generated_at: str
    engine_version: str

    def __post_init__(self) -> None:
        """Defensively copy caller-owned iterables."""
        object.__setattr__(
            self,
            "data_snapshot",
            tuple((key, value) for key, value in self.data_snapshot),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain dashboard bundle data."""
        return {
            "id": self.id,
            "html_file": self.html_file,
            "data_snapshot": [list(item) for item in self.data_snapshot],
            "generated_at": self.generated_at,
            "engine_version": self.engine_version,
        }
