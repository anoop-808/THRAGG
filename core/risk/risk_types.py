"""
core.risk.types
=================

Shared type aliases for the Risk Engine.

chain_data dicts flow through nearly every factor, engine, and the policy
matcher as a bare `dict[str, Any]`. That's accurate but not very
informative at a call site. ChainData documents the known/expected keys
that RiskBuilder._normalize_chain_data() guarantees, without forcing a
full dataclass rewrite (the dict shape is intentionally open-ended —
callers may pass extra domain-specific keys through).

total=False: every key is optional, since callers get default keys
via .get() throughout the factor implementations. This is documentation,
not runtime enforcement — factors should keep using chain_data.get(...)
defensively, exactly as before.
"""

from __future__ import annotations

from typing import Any, TypedDict


class ChainData(TypedDict, total=False):
    """Normalized attack-chain dict produced by RiskBuilder._normalize_chain_data()."""
    id: str
    entity_types: list[str]
    entities: list[str]
    stage_count: int
    timeline: list[Any]
    has_internet_exposure: bool
    has_privileged_identity: bool
    privilege_level: str
    confidence: str
    severity: str
    primary_asset: str
    primary_asset_composite_impact: float
    primary_asset_environment: str
    primary_category: str
    entry_point_type: str
    entry_point: str
