from dataclasses import FrozenInstanceError
from typing import get_type_hints

import pytest

from thragg.core.evidence_package import (
    EvidencePackage,
    EvidencePackageManifest,
    stable_evidence_package_id,
)
from thragg.core.evidence_package_schema import (
    EvidencePackageSchema,
    EvidencePackageSchemaError,
)
from thragg.core.report_renderer import ReportRenderer


def _manifest(**overrides) -> EvidencePackageManifest:
    defaults = dict(
        package_id="pkg-manifest-1",
        generated_at="2026-07-04T00:00:00Z",
        engine_version="m9-contracts",
        thragg_version="1.0",
        files=("executive.md", "snapshot.json"),
        snapshot_summary=(("risk_count", "2"), ("attack_chain_count", "1")),
    )
    defaults.update(overrides)
    return EvidencePackageManifest(**defaults)


def _package(**overrides) -> EvidencePackage:
    manifest = overrides.pop("manifest", _manifest())
    files_written = overrides.pop("files_written", ("executive.md", "snapshot.json"))
    generated_at = overrides.pop("generated_at", "2026-07-04T00:00:00Z")
    output_directory = overrides.pop("output_directory", "/tmp/thragg")
    defaults = dict(
        id=stable_evidence_package_id(
            getattr(manifest, "package_id", "pkg-manifest-1"),
            output_directory,
            files_written,
            generated_at,
        ),
        manifest=manifest,
        output_directory=output_directory,
        files_written=files_written,
        generated_at=generated_at,
        framework_version="1.0",
    )
    defaults.update(overrides)
    return EvidencePackage(**defaults)


def test_report_renderer_is_protocol_only():
    hints = get_type_hints(ReportRenderer.render)

    assert hints["return"] is str
    assert "format" in ReportRenderer.__annotations__
    assert "content_type" in ReportRenderer.__annotations__
    assert not hasattr(ReportRenderer, "to_dict")


def test_manifest_is_frozen_tuple_backed_serializable_and_validated():
    manifest = EvidencePackageManifest(
        package_id="pkg-manifest-1",
        generated_at="2026-07-04T00:00:00Z",
        engine_version="m9-contracts",
        thragg_version="1.0",
        files=["executive.md", "snapshot.json"],
        snapshot_summary=[["risk_count", "2"], ("attack_chain_count", "1")],
    )

    assert EvidencePackageSchema.is_valid_manifest(manifest) is True
    assert manifest.files == ("executive.md", "snapshot.json")
    assert manifest.snapshot_summary == (
        ("risk_count", "2"),
        ("attack_chain_count", "1"),
    )
    assert manifest.to_dict() == {
        "package_id": "pkg-manifest-1",
        "generated_at": "2026-07-04T00:00:00Z",
        "engine_version": "m9-contracts",
        "thragg_version": "1.0",
        "files": ["executive.md", "snapshot.json"],
        "snapshot_summary": [["risk_count", "2"], ["attack_chain_count", "1"]],
    }
    with pytest.raises(FrozenInstanceError):
        manifest.files = ()


def test_manifest_validation_rejects_blank_strings_and_non_tuple_fields():
    with pytest.raises(EvidencePackageSchemaError):
        EvidencePackageSchema.validate_manifest(_manifest(package_id=" "))

    manifest = _manifest(files=("executive.md", " "))
    with pytest.raises(EvidencePackageSchemaError):
        EvidencePackageSchema.validate_manifest(manifest)


def test_manifest_validation_rejects_invalid_nested_summary():
    manifest = _manifest(snapshot_summary=(("risk_count", ""),))

    with pytest.raises(EvidencePackageSchemaError):
        EvidencePackageSchema.validate_manifest(manifest)


def test_package_is_frozen_nested_serializable_and_validated():
    package = _package(files_written=["executive.md", "snapshot.json"])

    assert EvidencePackageSchema.is_valid_package(package) is True
    assert package.files_written == ("executive.md", "snapshot.json")
    assert package.to_dict()["id"] == "pkg-e88865c56bd56328"
    assert package.to_dict()["manifest"]["package_id"] == "pkg-manifest-1"
    assert package.to_dict()["files_written"] == ["executive.md", "snapshot.json"]
    assert package.to_dict()["framework_version"] == "1.0"
    with pytest.raises(FrozenInstanceError):
        package.generated_at = "changed"


def test_package_validation_rejects_bad_nested_manifest_and_ids():
    package = _package(manifest="manifest")
    with pytest.raises(EvidencePackageSchemaError):
        EvidencePackageSchema.validate_package(package)

    package = _package(id="bad id")
    with pytest.raises(EvidencePackageSchemaError):
        EvidencePackageSchema.validate_package(package)

    package = _package(framework_version=" ")
    with pytest.raises(EvidencePackageSchemaError):
        EvidencePackageSchema.validate_package(package)


def test_stable_evidence_package_id_is_deterministic():
    first = stable_evidence_package_id(
        "pkg-manifest-1",
        "/tmp/thragg",
        ("executive.md", "snapshot.json"),
        "2026-07-04T00:00:00Z",
    )
    second = stable_evidence_package_id(
        "pkg-manifest-1",
        "/tmp/thragg",
        ("executive.md", "snapshot.json"),
        "2026-07-04T00:00:00Z",
    )
    changed = stable_evidence_package_id(
        "pkg-manifest-1",
        "/tmp/thragg",
        ("executive.md",),
        "2026-07-04T00:00:00Z",
    )

    assert first == second
    assert first == "pkg-e88865c56bd56328"
    assert first != changed
