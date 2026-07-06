"""
core.risk.factor_registry
===========================

FactorRegistry — the single place that knows which concrete RiskFactor
implementations make up "likelihood" and "impact".

Before: LikelihoodEngine and ImpactEngine each hardcoded their own
`_default_*_factors()` function, importing concrete factor classes
directly. RiskBuilder never touched factors directly, but the engines
did, which made swapping/extending the factor set a two-file change.

Now: FactorRegistry owns the default factor tuples. LikelihoodEngine and
ImpactEngine ask the registry for factors instead of instantiating them
inline. Extending the factor set (e.g. adding a new likelihood factor)
means registering it here — engines don't change.

Backward compatibility: LikelihoodEngine() / ImpactEngine() with no
arguments still produce the exact same factor set, in the exact same
order, as before.
"""

from __future__ import annotations

from .risk_factor import RiskFactor
from .risk_factors_likelihood import (
    AttackChainCompletenessFactor,
    ChainConfidenceFactor,
    IdentityPrivilegeFactor,
    InternetExposureFactor,
)
from .risk_factors_impact import (
    AssetCriticalityFactor,
    BlastRadiusFactor,
    EnvironmentFactor,
    SeverityFactor,
)


class FactorRegistry:
    """
    Provides the default (or a custom) set of likelihood/impact factors.

    Engines depend on this registry, not on individual factor classes:

        engine = LikelihoodEngine(factors=FactorRegistry().likelihood_factors())

    To extend, either subclass and override the two methods below, or
    construct with explicit tuples:

        registry = FactorRegistry(
            likelihood_factors=(MyCustomFactor(), *FactorRegistry().likelihood_factors()),
        )
    """

    def __init__(
        self,
        likelihood_factors: tuple[RiskFactor, ...] | None = None,
        impact_factors: tuple[RiskFactor, ...] | None = None,
    ) -> None:
        self._likelihood_factors = likelihood_factors or (
            InternetExposureFactor(),
            IdentityPrivilegeFactor(),
            ChainConfidenceFactor(),
            AttackChainCompletenessFactor(),
        )
        self._impact_factors = impact_factors or (
            AssetCriticalityFactor(),
            BlastRadiusFactor(),
            SeverityFactor(),
            EnvironmentFactor(),
        )

    def likelihood_factors(self) -> tuple[RiskFactor, ...]:
        return self._likelihood_factors

    def impact_factors(self) -> tuple[RiskFactor, ...]:
        return self._impact_factors


# Shared default instance — avoids re-instantiating factor tuples on every
# LikelihoodEngine()/ImpactEngine() call when no custom registry is given.
DEFAULT_FACTOR_REGISTRY = FactorRegistry()
