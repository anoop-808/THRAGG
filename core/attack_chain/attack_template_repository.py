"""
core.attack_template_repository
================================

Load attack templates from JSON configuration.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from .attack_chain_schema import validate_attack_template
from .attack_template import AttackTemplate
from ..foundation.finding import Severity

if TYPE_CHECKING:
    from .attack_chain_rule import AttackChainRule

__all__ = ["AttackTemplateRepository"]


class AttackTemplateRepository:
    """Load attack templates from JSON without changing engine code."""

    def __init__(
        self,
        templates: tuple[AttackTemplate, ...] | None = None,
        path: Path | None = None,
    ) -> None:
        if templates is not None:
            self._templates = self._validated(templates)
        elif path is not None:
            self._templates = self.from_json(path)
        else:
            self._templates = self.from_json(
                Path(__file__).with_name("attack_templates.json")
            )

    def list(self) -> tuple[AttackTemplate, ...]:
        """Return templates in deterministic order."""
        return tuple(sorted(self._templates, key=lambda t: t.id))

    def get(self, template_id: str) -> AttackTemplate | None:
        """Return one template by id."""
        return next((t for t in self._templates if t.id == template_id), None)

    @staticmethod
    def from_json(path: Path) -> tuple[AttackTemplate, ...]:
        """Load templates from a JSON file."""
        data = json.loads(path.read_text(encoding="utf-8"))
        return AttackTemplateRepository._validated(tuple(
            AttackTemplate(**{**item, "severity": Severity(item["severity"])})
            for item in data["templates"]
        ))

    @staticmethod
    def _validated(
        templates: tuple[AttackTemplate, ...],
    ) -> tuple[AttackTemplate, ...]:
        for template in templates:
            validate_attack_template(template)
        return templates

    def find_by_entry_point(self, entry_point_type: str) -> tuple[AttackTemplate, ...]:
        """Return templates matching an entry point type."""
        return tuple(
            t for t in self._templates if t.entry_point_type == entry_point_type
        )
