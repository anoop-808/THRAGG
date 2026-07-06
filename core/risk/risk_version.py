"""
core.risk.version
==================

Single source of truth for every version string used across the Risk Engine.

Previously ENGINE_VERSION / POLICY_VERSION lived in risk_builder.py and
CALCULATION_VERSION lived in risk_calculator.py. Bumping one without the
other was an easy mistake. They now live here, together, with a single
place to bump when the scoring formula, policy schema, or engine as a
whole changes.

Bump rules:
- ENGINE_VERSION:      any change to the Risk Engine pipeline/behavior.
- POLICY_VERSION:      any change to the Policy schema or evaluation rules.
- CALCULATION_VERSION: any change to the likelihood/impact/risk formula
                        or factor weights (see scoring_policy.py).
"""

from __future__ import annotations

ENGINE_VERSION: str = "thragg-risk-engine-1.0"
POLICY_VERSION: str = "1.0"
CALCULATION_VERSION: str = "1.0"
