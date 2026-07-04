"""
core.attack_chain_repository
============================

In-memory repository for generated AttackChain objects.
"""

from __future__ import annotations

import hashlib

from .attack_chain import AttackChain

__all__ = ["AttackChainRepository", "attack_chain_duplicate_key"]


def attack_chain_duplicate_key(chain: AttackChain) -> str:
    """Return duplicate key from sorted correlation ids."""
    raw = "|".join(sorted(chain.correlations))
    return hashlib.sha256(raw.encode()).hexdigest()


class AttackChainRepository:
    """Store attack chains and skip duplicates."""

    def __init__(self) -> None:
        self._chains: dict[str, AttackChain] = {}
        self._duplicate_keys: set[str] = set()

    def add(self, chain: AttackChain) -> bool:
        """Store a chain, returning False when duplicate."""
        key = attack_chain_duplicate_key(chain)
        if key in self._duplicate_keys:
            return False
        self._duplicate_keys.add(key)
        self._chains[chain.id] = chain
        return True

    def list(self) -> tuple[AttackChain, ...]:
        """Return stored chains in deterministic id order."""
        return tuple(self._chains[item_id] for item_id in sorted(self._chains))

    def __len__(self) -> int:
        return len(self._chains)
