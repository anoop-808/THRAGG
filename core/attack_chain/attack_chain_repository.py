"""
core.attack_chain_repository
============================

In-memory repository for generated AttackChain objects.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace

from .attack_chain import AttackChain
from .attack_chain_schema import is_valid_attack_chain

__all__ = ["AttackChainRepository", "attack_chain_duplicate_key"]


SEVERITY_PRIORITY = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
CONFIDENCE_PRIORITY = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def attack_chain_duplicate_key(chain: AttackChain) -> str:
    """Return duplicate key from stable chain content."""
    parts = chain.correlations or tuple(
        f"{step.mitre_id}:{step.entity}" for step in chain.steps
    )
    raw = "|".join(sorted(parts))
    return hashlib.sha256(raw.encode()).hexdigest()


class AttackChainRepository:
    """In-memory store for finalized attack chains."""

    def __init__(self) -> None:
        self._chains: dict[str, AttackChain] = {}
        self._duplicate_keys: set[str] = set()

    def add(self, chain: AttackChain) -> bool:
        """Store a valid chain, merging duplicates."""
        if not is_valid_attack_chain(chain):
            return False
        key = attack_chain_duplicate_key(chain)
        if key in self._duplicate_keys:
            existing_id = next(
                item_id
                for item_id, item in self._chains.items()
                if attack_chain_duplicate_key(item) == key
            )
            self._chains[existing_id] = self._merge(self._chains[existing_id], chain)
            return False
        self._duplicate_keys.add(key)
        self._chains[chain.chain_id] = chain
        self.remove_overlapping_chains()
        return True

    def get(self, chain_id: str) -> AttackChain | None:
        """Lookup one chain by id."""
        return self._chains.get(chain_id)

    def list(self) -> tuple[AttackChain, ...]:
        """Return stored chains in deterministic id order."""
        return tuple(self._chains[item_id] for item_id in sorted(self._chains))

    def all(self) -> tuple[AttackChain, ...]:
        """Alias for repository interfaces that use all()."""
        return self.list()

    def query(
        self,
        *,
        severity: str | None = None,
        confidence: str | None = None,
        template_id: str | None = None,
        entity: str | None = None,
        technique: str | None = None,
    ) -> tuple[AttackChain, ...]:
        """Return chains matching simple exact-match filters."""
        chains = self.list()
        if severity is not None:
            chains = tuple(chain for chain in chains if chain.severity.value == severity)
        if confidence is not None:
            chains = tuple(chain for chain in chains if chain.confidence.value == confidence)
        if template_id is not None:
            chains = tuple(chain for chain in chains if chain.template_id == template_id)
        if entity is not None:
            chains = tuple(chain for chain in chains if entity in chain.participating_entities)
        if technique is not None:
            chains = tuple(chain for chain in chains if technique in chain.mitre_techniques)
        return chains

    def merge_duplicate_chains(self) -> None:
        """Merge chains with the same duplicate key."""
        merged: dict[str, AttackChain] = {}
        for chain in self.list():
            key = attack_chain_duplicate_key(chain)
            merged[key] = self._merge(merged[key], chain) if key in merged else chain
        self._chains = {chain.chain_id: chain for chain in merged.values()}
        self._duplicate_keys = set(merged)

    def remove_overlapping_chains(self) -> None:
        """Keep the strongest narrative and preserve overlapping evidence."""
        kept: list[AttackChain] = []
        for chain in sorted(self._chains.values(), key=self._rank, reverse=True):
            overlap_index = next(
                (
                    index
                    for index, existing in enumerate(kept)
                    if self._overlaps(chain, existing)
                ),
                None,
            )
            if overlap_index is None:
                kept.append(chain)
            else:
                kept[overlap_index] = self._merge(kept[overlap_index], chain)
        self._chains = {chain.chain_id: chain for chain in kept}
        self._duplicate_keys = {
            attack_chain_duplicate_key(chain) for chain in self._chains.values()
        }

    def __len__(self) -> int:
        return len(self._chains)

    def _merge(self, first: AttackChain, second: AttackChain) -> AttackChain:
        strongest = max((first, second), key=self._rank)
        return replace(
            strongest,
            correlations=tuple(sorted(set(first.correlations) | set(second.correlations))),
            supporting_findings=tuple(
                sorted(set(first.supporting_findings) | set(second.supporting_findings))
            ),
            participating_entities=tuple(
                sorted(set(first.participating_entities) | set(second.participating_entities))
            ),
            entities=tuple(
                sorted(set(first.entities) | set(second.entities))
            ),
            participating_relationships=tuple(
                sorted(
                    set(first.participating_relationships)
                    | set(second.participating_relationships)
                )
            ),
            relationships=tuple(
                sorted(set(first.relationships) | set(second.relationships))
            ),
            mitre_techniques=tuple(
                sorted(set(first.mitre_techniques) | set(second.mitre_techniques))
            ),
        )

    def _rank(self, chain: AttackChain) -> tuple[int, int, int]:
        return (
            SEVERITY_PRIORITY[chain.severity.value],
            CONFIDENCE_PRIORITY[chain.confidence.value],
            len(chain.steps),
        )

    def _overlaps(self, first: AttackChain, second: AttackChain) -> bool:
        return bool(
            set(first.supporting_findings) & set(second.supporting_findings)
            or set(first.participating_relationships)
            & set(second.participating_relationships)
        )
