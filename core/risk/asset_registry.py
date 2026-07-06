"""
core.risk.asset_registry
========================

Asset profile lookup for the Risk Engine.
"""

from __future__ import annotations

import logging

from .asset_profiles import (
    BUILTIN_KEYWORD_MAP,
    BUILTIN_PROFILES,
    DEFAULT_BUSINESS_VALUE,
    DEFAULT_CRITICALITY,
    AssetProfile,
)

__all__ = [
    "AssetProfile",
    "AssetRegistry",
    "DEFAULT_BUSINESS_VALUE",
    "DEFAULT_CRITICALITY",
]

LOGGER = logging.getLogger(__name__)


class AssetRegistry:
    """Look up asset profiles by exact name or keyword."""

    def __init__(
        self,
        profiles: list[AssetProfile] | tuple[AssetProfile, ...] | None = None,
        keyword_map: dict[str, str] | None = None,
    ) -> None:
        self._profiles = {
            profile.name: profile
            for profile in (BUILTIN_PROFILES if profiles is None else profiles)
        }
        self._keyword_map = dict(
            BUILTIN_KEYWORD_MAP if keyword_map is None else keyword_map
        )

    def register(self, profile: AssetProfile) -> None:
        """Register one profile."""
        self._profiles[profile.name] = profile

    def register_keyword(self, keyword: str, profile_name: str) -> None:
        """Register one keyword-to-profile mapping."""
        self._keyword_map[keyword] = profile_name

    def lookup(self, asset_name: str) -> AssetProfile:
        """Return a matching asset profile or a deterministic default."""
        normalized = asset_name.lower().replace("-", "_").replace(" ", "_")
        if normalized in self._profiles:
            return self._profiles[normalized]
        for keyword, profile_name in self._keyword_map.items():
            if keyword in normalized and profile_name in self._profiles:
                return self._profiles[profile_name]
        LOGGER.warning(
            "Unknown asset %r; using default criticality=%d.",
            asset_name,
            DEFAULT_CRITICALITY,
        )
        return AssetProfile(
            name=f"unknown:{asset_name}",
            criticality=DEFAULT_CRITICALITY,
            business_value=DEFAULT_BUSINESS_VALUE,
            environment="unknown",
            confidentiality=50,
            integrity=50,
            availability=50,
        )
