"""
core.risk.asset_profiles
========================

Built-in AssetProfile data for the Risk Engine.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "AssetProfile",
    "BUILTIN_KEYWORD_MAP",
    "BUILTIN_PROFILES",
    "DEFAULT_BUSINESS_VALUE",
    "DEFAULT_CRITICALITY",
]

DEFAULT_CRITICALITY = 60
DEFAULT_BUSINESS_VALUE = 50


@dataclass(frozen=True)
class AssetProfile:
    """Business and security importance for a known asset type."""

    name: str
    criticality: int
    business_value: int
    environment: str
    confidentiality: int
    integrity: int
    availability: int

    @property
    def cia_score(self) -> float:
        """Return normalized average CIA score."""
        return (self.confidentiality + self.integrity + self.availability) / 3.0

    @property
    def composite_impact(self) -> float:
        """Return weighted composite impact."""
        return (
            self.criticality * 0.4
            + self.business_value * 0.3
            + self.cia_score * 0.3
        )


BUILTIN_PROFILES: tuple[AssetProfile, ...] = (
    AssetProfile("domain_controller", 100, 100, "prod", 100, 100, 100),
    AssetProfile("production_sql", 95, 90, "prod", 100, 95, 90),
    AssetProfile("azure_subscription", 90, 85, "prod", 90, 85, 80),
    AssetProfile("key_vault", 95, 90, "prod", 100, 100, 85),
    AssetProfile("developer_workstation", 55, 50, "dev", 60, 55, 40),
    AssetProfile("test_vm", 20, 15, "test", 20, 20, 20),
    AssetProfile("public_web_server", 75, 70, "prod", 70, 85, 95),
    AssetProfile("identity_provider", 100, 100, "prod", 100, 100, 95),
)

BUILTIN_KEYWORD_MAP: dict[str, str] = {
    "dc": "domain_controller",
    "domain_controller": "domain_controller",
    "sql": "production_sql",
    "database": "production_sql",
    "db": "production_sql",
    "subscription": "azure_subscription",
    "azure": "azure_subscription",
    "vault": "key_vault",
    "keyvault": "key_vault",
    "workstation": "developer_workstation",
    "laptop": "developer_workstation",
    "test": "test_vm",
    "web": "public_web_server",
    "identity": "identity_provider",
    "idp": "identity_provider",
}
