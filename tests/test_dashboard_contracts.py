from dataclasses import FrozenInstanceError

import pytest

from thragg.core.dashboard_bundle import (
    DashboardBundle,
    stable_dashboard_bundle_id,
)
from thragg.core.dashboard_schema import DashboardSchema, DashboardSchemaError
from thragg.core.dashboard_view import DashboardView


def _bundle(**overrides) -> DashboardBundle:
    data_snapshot = overrides.pop(
        "data_snapshot",
        (("risk_count", "2"), ("attack_chain_count", "1")),
    )
    generated_at = overrides.pop("generated_at", "2026-07-04T00:00:00Z")
    engine_version = overrides.pop("engine_version", "m10-contracts")
    html_file = overrides.pop("html_file", "dashboard.html")
    bundle_id = overrides.pop("id", None) or stable_dashboard_bundle_id(
        html_file,
        data_snapshot,
        generated_at,
        engine_version,
    )
    defaults = dict(
        id=bundle_id,
        html_file=html_file,
        data_snapshot=data_snapshot,
        generated_at=generated_at,
        engine_version=engine_version,
    )
    defaults.update(overrides)
    return DashboardBundle(**defaults)


def test_dashboard_view_enum_contains_only_m10_contract_values():
    assert [item.value for item in DashboardView] == [
        "EXECUTIVE_SUMMARY",
        "RISK_PRIORITY",
        "ATTACK_CHAINS",
        "CORRELATIONS",
        "KNOWLEDGE_GRAPH",
        "MITRE_MATRIX",
        "EVIDENCE_EXPLORER",
    ]


def test_dashboard_bundle_is_frozen_tuple_backed_and_serializable():
    bundle = _bundle(data_snapshot=[["risk_count", "2"], ("attack_chain_count", "1")])

    assert DashboardSchema.is_valid_bundle(bundle) is True
    assert bundle.data_snapshot == (("risk_count", "2"), ("attack_chain_count", "1"))
    assert bundle.to_dict() == {
        "id": "dash-d1ad202434759ed8",
        "html_file": "dashboard.html",
        "data_snapshot": [["risk_count", "2"], ["attack_chain_count", "1"]],
        "generated_at": "2026-07-04T00:00:00Z",
        "engine_version": "m10-contracts",
    }
    with pytest.raises(FrozenInstanceError):
        bundle.html_file = "changed.html"


def test_dashboard_schema_validates_ids_paths_timestamps_and_views():
    DashboardSchema.validate_bundle(_bundle())
    DashboardSchema.validate_views(
        (DashboardView.EXECUTIVE_SUMMARY, DashboardView.RISK_PRIORITY)
    )

    with pytest.raises(DashboardSchemaError):
        DashboardSchema.validate_bundle(_bundle(id="bad id"))
    with pytest.raises(DashboardSchemaError):
        DashboardSchema.validate_bundle(_bundle(html_file="dashboard.txt"))
    with pytest.raises(DashboardSchemaError):
        DashboardSchema.validate_bundle(_bundle(generated_at="not-a-date"))
    with pytest.raises(DashboardSchemaError):
        DashboardSchema.validate_views(("EXECUTIVE_SUMMARY",))


def test_dashboard_schema_rejects_invalid_data_snapshot():
    with pytest.raises(DashboardSchemaError):
        DashboardSchema.validate_bundle(_bundle(data_snapshot=(("risk_count", ""),)))

    with pytest.raises(DashboardSchemaError):
        DashboardSchema.validate_bundle(
            _bundle(id="dash-invalid", data_snapshot=(("risk_count", 2),))
        )


def test_stable_dashboard_bundle_id_is_deterministic():
    first = stable_dashboard_bundle_id(
        "dashboard.html",
        (("risk_count", "2"), ("attack_chain_count", "1")),
        "2026-07-04T00:00:00Z",
        "m10-contracts",
    )
    second = stable_dashboard_bundle_id(
        "dashboard.html",
        (("risk_count", "2"), ("attack_chain_count", "1")),
        "2026-07-04T00:00:00Z",
        "m10-contracts",
    )
    changed = stable_dashboard_bundle_id(
        "dashboard.html",
        (("risk_count", "3"),),
        "2026-07-04T00:00:00Z",
        "m10-contracts",
    )

    assert first == second
    assert first == "dash-d1ad202434759ed8"
    assert first != changed
