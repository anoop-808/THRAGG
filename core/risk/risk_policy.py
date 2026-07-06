"""
core.risk.policy
================

Policy contract and loader for the Risk Policy Engine.

The Risk Engine never reads YAML directly.
PolicyLoader is the only boundary between raw config and Policy objects.
The engine consumes Policy[] exclusively.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .risk_exceptions import PolicyError


class PolicyType(str, Enum):
    ACCEPTED_RISK = "ACCEPTED_RISK"
    TEMPORARY_EXCEPTION = "TEMPORARY_EXCEPTION"
    MAINTENANCE_WINDOW = "MAINTENANCE_WINDOW"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BUSINESS_EXCEPTION = "BUSINESS_EXCEPTION"


class PolicyAction(str, Enum):
    ACCEPT = "ACCEPT"          # accepted, still shown, deprioritized
    SUPPRESS = "SUPPRESS"      # excluded from priority ranking
    DOWNGRADE = "DOWNGRADE"    # reduce effective risk score


@dataclass(frozen=True)
class PolicyMatchCriteria:
    """
    Deterministic match criteria evaluated against an AttackChain.
    All fields are optional. A policy matches when ALL provided
    criteria match the target chain.
    """
    chain_id: Optional[str] = None
    category: Optional[str] = None
    min_severity: Optional[str] = None   # matches chains AT or ABOVE this level
    entity_types: tuple[str, ...] = ()   # matches if chain contains ANY listed type
    entry_point_type: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "entity_types", tuple(self.entity_types))

    def matches(self, chain_data: dict[str, Any]) -> bool:
        """Return True when all non-None criteria match the chain_data dict."""
        if self.chain_id and chain_data.get("id") != self.chain_id:
            return False
        if self.category and chain_data.get("primary_category") != self.category:
            return False
        if self.entry_point_type and chain_data.get("entry_point_type") != self.entry_point_type:
            return False
        if self.entity_types:
            chain_entity_types = set(chain_data.get("entity_types", []))
            if not chain_entity_types.intersection(self.entity_types):
                return False
        return True


@dataclass(frozen=True)
class Policy:
    """
    Immutable policy object. Produced by PolicyLoader.
    Consumed by RiskPolicyEngine. Never parsed inside the engine itself.
    """
    id: str
    type: PolicyType
    action: PolicyAction
    match_criteria: PolicyMatchCriteria
    reason: str
    expiration: Optional[str] = None      # ISO 8601 date string or None = no expiry
    score_modifier: float = 0.0           # used only when action == DOWNGRADE

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "action": self.action.value,
            "reason": self.reason,
            "expiration": self.expiration,
            "score_modifier": self.score_modifier,
        }


def _stable_policy_id(policy_id_raw: str) -> str:
    digest = hashlib.sha256(policy_id_raw.encode()).hexdigest()[:12]
    return f"policy-{digest}"


class PolicyLoader:
    """
    Boundary between raw configuration (YAML, dict, etc.) and Policy objects.

    The Risk Engine never calls this directly.
    Callers load policies and pass Policy[] into the engine.

    Supports:
      - load_from_dicts(): for programmatic / test usage
      - load_from_yaml(): for file-based configuration
    """

    @staticmethod
    def load_from_dicts(raw_policies: list[dict[str, Any]]) -> list[Policy]:
        """Parse a list of raw dicts into Policy objects."""
        policies: list[Policy] = []
        for raw in raw_policies:
            criteria_raw = raw.get("match_criteria", {})
            criteria = PolicyMatchCriteria(
                chain_id=criteria_raw.get("chain_id"),
                category=criteria_raw.get("category"),
                min_severity=criteria_raw.get("min_severity"),
                entity_types=tuple(criteria_raw.get("entity_types", [])),
                entry_point_type=criteria_raw.get("entry_point_type"),
            )
            try:
                policy = Policy(
                    id=raw.get("id") or _stable_policy_id(str(raw)),
                    type=PolicyType(raw["type"]),
                    action=PolicyAction(raw["action"]),
                    match_criteria=criteria,
                    reason=raw.get("reason", ""),
                    expiration=raw.get("expiration"),
                    score_modifier=float(raw.get("score_modifier", 0.0)),
                )
            except (KeyError, ValueError) as exc:
                raise PolicyError(f"Malformed policy spec {raw!r}: {exc}") from exc
            policies.append(policy)
        return policies

    @staticmethod
    def load_from_yaml(path: str) -> list[Policy]:
        """
        Load policies from a YAML file.
        Requires PyYAML. Falls back to empty list with a warning if unavailable.
        """
        try:
            import yaml  # type: ignore
        except ImportError:
            import warnings
            warnings.warn(
                "PyYAML is not installed. Returning empty policy list. "
                "Install pyyaml or use PolicyLoader.load_from_dicts().",
                stacklevel=2,
            )
            return []

        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or []

        return PolicyLoader.load_from_dicts(raw if isinstance(raw, list) else [])
