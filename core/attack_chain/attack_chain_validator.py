"""
core.attack_chain_validator
===========================

Strict validation for finalized AttackChain objects.
"""

from __future__ import annotations

import re

from .attack_chain import AttackChain

__all__ = ["AttackChainValidationError", "AttackChainValidator"]


MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class AttackChainValidationError(ValueError):
    """Raised when a finalized attack chain is invalid."""


class AttackChainValidator:
    """Reject invalid attack chains before they reach consumers."""

    def validate(self, chain: AttackChain) -> None:
        """Validate a finalized chain, raising on the first violation."""
        if not chain.entry_point.strip():
            raise AttackChainValidationError("AttackChain.entry_point is required")
        from .attack_template_repository import AttackTemplateRepository
        repo = AttackTemplateRepository()
        template = repo.get(chain.template_id)

        min_steps = getattr(template, "min_steps", 2) if template else 2

        if len(chain.steps) < min_steps:
            raise AttackChainValidationError(f"AttackChain requires at least {min_steps} steps")

        for step in chain.steps:
            if not step.evidence:
                raise AttackChainValidationError("AttackStep.evidence is required")
            if not MITRE_TECHNIQUE_RE.fullmatch(step.mitre_id):
                raise AttackChainValidationError(
                    f"AttackStep.mitre_id is invalid: {step.mitre_id}"
                )

    def is_valid(self, chain: AttackChain) -> bool:
        """Return True when a chain passes finalized-chain validation."""
        try:
            self.validate(chain)
            return True
        except AttackChainValidationError:
            return False
