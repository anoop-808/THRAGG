import pytest

from thragg.core import Entity as ExportedEntity
from thragg.core import EntityExtractor as ExportedEntityExtractor
from thragg.core import EntityType as ExportedEntityType
from thragg.core import EntityValidationError as ExportedEntityValidationError
from thragg.core import is_valid_entity as exported_is_valid_entity
from thragg.core import stable_entity_id as exported_stable_entity_id
from thragg.core import validate_entity as exported_validate_entity
from thragg.core.shared.constants import Confidence, EntityType, Severity
from thragg.core.foundation.entity import Entity, stable_entity_id
from thragg.core.foundation.entity_extractor import EntityExtractor
from thragg.core.foundation.entity_schema import (
    EntityValidationError,
    is_valid_entity,
    validate_entity,
)
from thragg.core.foundation.finding import Finding
from thragg.modules.example_nmap.module import run


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        id="NMAP-SSH-EXPOSED-10.0.0.5-22",
        title="SSH Service Exposed",
        description="SSH open on 10.0.0.5",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        category="Network Exposure",
        type="SSH_EXPOSED",
        entity_type=EntityType.HOST,
        asset="10.0.0.5",
        observed_at="2026-07-01T00:00:00Z",
        source_module="nmap",
        source_rule="NMAP-SSH-EXPOSED-001",
        evidence={"ip": "10.0.0.5", "port": 22},
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _entity(**overrides) -> Entity:
    defaults = dict(
        id="ent-test",
        type=EntityType.HOST,
        primary_identifier="10.0.0.5",
        source_module="nmap",
        source_finding="NMAP-SSH-EXPOSED-10.0.0.5-22",
        confidence=Confidence.HIGH,
        aliases=[],
        attributes={"port": 22},
    )
    defaults.update(overrides)
    return Entity(**defaults)


# ---------------------------------------------------------------------------
# Entity model
# ---------------------------------------------------------------------------
def test_entity_to_dict_serializes_plain_values_and_copies_mutables():
    entity = _entity(aliases=["web01"], attributes={"port": 22})

    serialized = entity.to_dict()

    assert serialized == {
        "id": "ent-test",
        "type": "HOST",
        "primary_identifier": "10.0.0.5",
        "aliases": ["web01"],
        "attributes": {"port": 22},
        "source_module": "nmap",
        "source_finding": "NMAP-SSH-EXPOSED-10.0.0.5-22",
        "confidence": "HIGH",
    }

    serialized["aliases"].append("mutated")
    serialized["attributes"]["port"] = 443
    assert entity.aliases == ["web01"]
    assert entity.attributes == {"port": 22}


def test_entity_dataclass_equality_uses_field_values():
    assert _entity() == _entity()
    assert _entity(primary_identifier="10.0.0.5") != _entity(
        primary_identifier="10.0.0.6"
    )


def test_core_public_api_exports_entity_subsystem():
    assert ExportedEntity is Entity
    assert ExportedEntityType is EntityType
    assert ExportedEntityExtractor is EntityExtractor
    assert ExportedEntityValidationError is EntityValidationError
    assert exported_stable_entity_id is stable_entity_id
    assert exported_validate_entity is validate_entity
    assert exported_is_valid_entity is is_valid_entity


# ---------------------------------------------------------------------------
# Stable IDs
# ---------------------------------------------------------------------------
def test_stable_entity_id_is_deterministic():
    assert stable_entity_id(EntityType.HOST, "10.0.0.5") == stable_entity_id(
        EntityType.HOST, "10.0.0.5"
    )


def test_stable_entity_id_differs_by_type():
    host_id = stable_entity_id(EntityType.HOST, "10.0.0.5")
    cloud_id = stable_entity_id(EntityType.CLOUD_RESOURCE, "10.0.0.5")
    assert host_id != cloud_id


def test_stable_entity_id_survives_serialization():
    entity_id = stable_entity_id(EntityType.USER, "admin")
    entity = _entity(
        id=entity_id,
        type=EntityType.USER,
        primary_identifier="admin",
        aliases=["root"],
    )
    assert entity.to_dict()["id"] == entity_id


def test_entity_id_is_not_changed_by_aliases():
    f1 = _make_finding(evidence={"ip": "10.0.0.5", "hostname": "web01"})
    f2 = _make_finding(
        evidence={
            "ip": "10.0.0.5",
            "hostname": "web01",
            "host": "web01",
        }
    )

    host1 = next(e for e in EntityExtractor.extract(f1) if e.type == EntityType.HOST)
    host2 = next(e for e in EntityExtractor.extract(f2) if e.type == EntityType.HOST)

    assert host1.id == host2.id
    assert host1.primary_identifier == host2.primary_identifier == "10.0.0.5"


def test_entity_id_is_not_changed_by_evidence_ordering():
    f1 = _make_finding(evidence={"ip": "10.0.0.5", "hostname": "web01"})
    f2 = _make_finding(evidence={"hostname": "web01", "ip": "10.0.0.5"})

    host1 = next(e for e in EntityExtractor.extract(f1) if e.type == EntityType.HOST)
    host2 = next(e for e in EntityExtractor.extract(f2) if e.type == EntityType.HOST)

    assert host1.id == host2.id
    assert host1.aliases == host2.aliases == ["web01"]


def test_repeated_and_batch_extraction_keep_same_ids():
    finding = _make_finding(evidence={"ip": "10.0.0.5", "user": "admin"})

    first = sorted(e.id for e in EntityExtractor.extract(finding))
    second = sorted(e.id for e in EntityExtractor.extract(finding))
    batch = sorted(e.id for e in EntityExtractor.extract_batch([finding]))

    assert first == second == batch


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def test_validate_entity_accepts_valid_entity():
    entity = _entity()
    validate_entity(entity)
    assert is_valid_entity(entity) is True


@pytest.mark.parametrize(
    "field_name",
    ("id", "primary_identifier", "source_module", "source_finding"),
)
def test_validate_entity_rejects_whitespace_required_strings(field_name):
    entity = _entity(**{field_name: "   "})

    assert is_valid_entity(entity) is False
    with pytest.raises(EntityValidationError, match=field_name):
        validate_entity(entity)


def test_validate_entity_rejects_bad_entity_type():
    entity = _entity(type="HOST")
    with pytest.raises(EntityValidationError, match="type"):
        validate_entity(entity)


def test_validate_entity_rejects_bad_confidence_type():
    entity = _entity(confidence="HIGH")
    with pytest.raises(EntityValidationError, match="confidence"):
        validate_entity(entity)


def test_validate_entity_rejects_whitespace_alias():
    entity = _entity(aliases=["web01", "   "])
    with pytest.raises(EntityValidationError, match="blank"):
        validate_entity(entity)


def test_validate_entity_rejects_duplicate_alias():
    entity = _entity(aliases=["web01", "web01"])
    with pytest.raises(EntityValidationError, match="duplicates"):
        validate_entity(entity)


def test_validate_entity_rejects_alias_equal_to_primary_identifier():
    entity = _entity(aliases=["10.0.0.5"])
    with pytest.raises(EntityValidationError, match="primary_identifier"):
        validate_entity(entity)


def test_validate_entity_rejects_invalid_alias_type():
    entity = _entity(aliases=["web01", 123])
    with pytest.raises(EntityValidationError, match=r"list\[str\]"):
        validate_entity(entity)


def test_validate_entity_rejects_non_dict_attributes():
    entity = _entity(attributes=[])
    with pytest.raises(EntityValidationError, match="attributes"):
        validate_entity(entity)


def test_validate_entity_rejects_non_string_attribute_keys():
    entity = _entity(attributes={1: "port"})
    with pytest.raises(EntityValidationError, match="keys"):
        validate_entity(entity)


# ---------------------------------------------------------------------------
# Alias handling
# ---------------------------------------------------------------------------
def test_hostname_and_ip_extract_ip_as_primary_and_hostname_as_alias():
    finding = _make_finding(
        asset="10.0.0.5",
        evidence={"hostname": "web01", "ip": "10.0.0.5"},
    )

    host = next(e for e in EntityExtractor.extract(finding) if e.type == EntityType.HOST)

    assert host.primary_identifier == "10.0.0.5"
    assert host.aliases == ["web01"]


def test_duplicate_aliases_are_removed_and_primary_alias_is_ignored():
    finding = _make_finding(
        evidence={
            "ip": "10.0.0.5",
            "host": "web01",
            "hostname": "web01",
            "source_ip": "10.0.0.5",
        }
    )

    host = next(e for e in EntityExtractor.extract(finding) if e.type == EntityType.HOST)

    assert host.primary_identifier == "10.0.0.5"
    assert host.aliases == ["web01"]


def test_alias_ordering_is_deterministic():
    f1 = _make_finding(
        evidence={"hostname": "web02", "host": "web01", "ip": "10.0.0.5"}
    )
    f2 = _make_finding(
        evidence={"ip": "10.0.0.5", "host": "web01", "hostname": "web02"}
    )

    host1 = next(e for e in EntityExtractor.extract(f1) if e.type == EntityType.HOST)
    host2 = next(e for e in EntityExtractor.extract(f2) if e.type == EntityType.HOST)

    assert host1.aliases == host2.aliases == ["web01", "web02"]


def test_blank_alias_candidates_are_ignored():
    finding = _make_finding(evidence={"ip": "10.0.0.5", "hostname": "   "})

    host = next(e for e in EntityExtractor.extract(finding) if e.type == EntityType.HOST)

    assert host.aliases == []


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------
def test_extract_primary_entity_from_finding():
    finding = _make_finding()

    entities = EntityExtractor.extract(finding)
    host = next(e for e in entities if e.primary_identifier == "10.0.0.5")

    assert host.type == EntityType.HOST
    assert host.source_finding == finding.id
    assert host.attributes.get("port") == 22


def test_extract_multiple_entity_types_from_one_finding():
    finding = _make_finding(evidence={"ip": "10.0.0.5", "user": "admin"})

    entities = EntityExtractor.extract(finding)
    identifiers = {e.primary_identifier for e in entities}

    assert identifiers == {"10.0.0.5", "admin"}
    user_entity = next(e for e in entities if e.primary_identifier == "admin")
    assert user_entity.type == EntityType.USER


def test_extract_dedupes_when_asset_equals_evidence_identifier():
    finding = _make_finding(asset="10.0.0.5", evidence={"ip": "10.0.0.5"})

    entities = EntityExtractor.extract(finding)
    ids = [e.id for e in entities]

    assert len(ids) == len(set(ids))


def test_extract_batch_from_multiple_findings():
    f1 = _make_finding()
    f2 = _make_finding(
        id="NMAP-SSH-EXPOSED-10.0.0.6-22",
        asset="10.0.0.6",
        evidence={"ip": "10.0.0.6", "port": 22},
    )

    entities = EntityExtractor.extract_batch([f1, f2])
    identifiers = {e.primary_identifier for e in entities}

    assert {"10.0.0.5", "10.0.0.6"} <= identifiers


def test_extract_batch_allows_duplicate_entities_across_findings():
    f1 = _make_finding(id="F-1")
    f2 = _make_finding(id="F-2")

    entities = EntityExtractor.extract_batch([f1, f2])
    host_entities = [e for e in entities if e.primary_identifier == "10.0.0.5"]

    assert len(host_entities) == 2
    assert host_entities[0].id == host_entities[1].id
    assert {e.source_finding for e in host_entities} == {"F-1", "F-2"}


@pytest.mark.parametrize(
    ("entity_type", "evidence_key", "identifier"),
    (
        (EntityType.HOST, "ip", "10.0.0.5"),
        (EntityType.USER, "user", "admin"),
        (EntityType.SERVICE, "service", "ssh"),
        (EntityType.APPLICATION, "application", "portal"),
        (EntityType.CONTAINER, "container", "api-1"),
        (EntityType.NETWORK, "network", "prod-vnet"),
        (EntityType.STORAGE, "storage", "logs-bucket"),
        (EntityType.DATABASE, "database", "orders-db"),
        (EntityType.CLOUD_RESOURCE, "cloud_resource", "vm-001"),
        (EntityType.IDENTITY, "identity", "spn-001"),
    ),
)
def test_extract_supports_every_mapped_entity_type(
    entity_type, evidence_key, identifier
):
    finding = _make_finding(asset=None, evidence={evidence_key: identifier})

    entities = EntityExtractor.extract(finding)

    assert len(entities) == 1
    assert entities[0].type == entity_type
    assert entities[0].primary_identifier == identifier


def test_extract_supports_unknown_primary_entity_type():
    finding = _make_finding(
        entity_type=EntityType.UNKNOWN,
        asset="mystery",
        evidence={},
    )

    entities = EntityExtractor.extract(finding)

    assert len(entities) == 1
    assert entities[0].type == EntityType.UNKNOWN
    assert entities[0].primary_identifier == "mystery"


def test_extract_returns_empty_list_for_empty_input():
    assert EntityExtractor.extract_batch([]) == []


def test_extract_returns_empty_list_for_empty_evidence_without_asset():
    finding = _make_finding(asset=None, evidence={})
    assert EntityExtractor.extract(finding) == []


def test_extract_ignores_unknown_evidence_keys():
    finding = _make_finding(asset=None, evidence={"unmapped": "value"})
    assert EntityExtractor.extract(finding) == []


def test_extract_ignores_none_and_whitespace_evidence_values():
    finding = _make_finding(
        asset=None,
        evidence={"ip": "   ", "user": None, "service": ""},
    )
    assert EntityExtractor.extract(finding) == []


@pytest.mark.parametrize(
    "bad_value",
    ({"name": "web01"}, ["web01"], ("web01",), {"web01"}),
)
def test_extract_ignores_malformed_identifier_values(bad_value):
    finding = _make_finding(asset=None, evidence={"hostname": bad_value})
    assert EntityExtractor.extract(finding) == []


def test_extract_ignores_malformed_evidence_container():
    finding = _make_finding(asset=None, evidence=["not", "a", "dict"])
    assert EntityExtractor.extract(finding) == []


def test_extract_trims_identifier_values():
    finding = _make_finding(asset=None, evidence={"user": "  admin  "})

    entities = EntityExtractor.extract(finding)

    assert len(entities) == 1
    assert entities[0].primary_identifier == "admin"


def test_none_asset_is_allowed_when_evidence_produces_entities():
    finding = _make_finding(asset=None, evidence={"user": "admin"})

    entities = EntityExtractor.extract(finding)

    assert len(entities) == 1
    assert entities[0].primary_identifier == "admin"


def test_none_asset_and_no_recognized_evidence_returns_empty_list():
    finding = _make_finding(asset=None, evidence={"ignored": "value"})
    assert EntityExtractor.extract(finding) == []


# ---------------------------------------------------------------------------
# Contract / backward compatibility
# ---------------------------------------------------------------------------
def test_contract_has_entities_field_alongside_existing_fields():
    parsed_scan = {
        "hosts": [{"ip": "10.0.0.5", "ports": [{"number": 22, "state": "open"}]}]
    }

    contract = run(parsed_scan, observed_at="2026-07-01T00:00:00Z")

    for field in ("metadata", "summary", "findings", "details", "artifacts", "errors"):
        assert field in contract

    assert "entities" in contract
    assert isinstance(contract["entities"], list)
    assert len(contract["entities"]) >= 1
    assert contract["entities"][0]["type"] == "HOST"


def test_contract_entities_empty_when_no_findings():
    parsed_scan = {
        "hosts": [{"ip": "10.0.0.5", "ports": [{"number": 443, "state": "open"}]}]
    }

    contract = run(parsed_scan)

    assert contract["findings"] == []
    assert contract["entities"] == []
