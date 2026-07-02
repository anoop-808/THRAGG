import pytest

from thragg.core import (
    IdentityResolver,
    ResolutionConfidence,
    ResolutionMethod,
    ResolutionRecord,
    ResolutionValidationError,
    ResolvedEntity,
    is_valid_resolution_record,
    is_valid_resolved_entity,
    stable_resolved_entity_id,
    validate_resolution_record,
    validate_resolved_entity,
)
from thragg.core.entity import Entity
from thragg.core.entity_schema import EntityValidationError
from thragg.core.finding import Confidence, EntityType


def _entity(**overrides) -> Entity:
    defaults = dict(
        id="ent-1",
        type=EntityType.HOST,
        primary_identifier="10.0.0.5",
        source_module="nmap",
        source_finding="finding-1",
        confidence=Confidence.HIGH,
        aliases=[],
        attributes={"port": 22},
    )
    defaults.update(overrides)
    return Entity(**defaults)


def _record(**overrides) -> ResolutionRecord:
    defaults = dict(
        resolution_method=ResolutionMethod.EXACT_IDENTIFIER,
        resolution_reason="exact primary identifier matched",
        resolution_confidence=ResolutionConfidence.HIGH,
        timestamp="2026-07-02T00:00:00+00:00",
        resolver_version="1.0.0",
        supporting_entities=["ent-1", "ent-2"],
    )
    defaults.update(overrides)
    return ResolutionRecord(**defaults)


def _resolved(**overrides) -> ResolvedEntity:
    defaults = dict(
        id="resolved-host-test",
        entity_type=EntityType.HOST,
        primary_identifier="10.0.0.5",
        aliases=["web01"],
        source_entities=["ent-1"],
        source_findings=["finding-1"],
        source_modules=["nmap"],
        attributes={"port": 22},
        resolution_records=[],
    )
    defaults.update(overrides)
    return ResolvedEntity(**defaults)


def test_resolved_entity_to_dict_serializes_plain_values_and_copies_mutables():
    resolved = _resolved(resolution_records=[_record()])

    data = resolved.to_dict()

    assert data["entity_type"] == "HOST"
    assert data["aliases"] == ["web01"]
    assert data["resolution_records"][0]["resolution_method"] == "EXACT_IDENTIFIER"

    data["aliases"].append("mutated")
    data["attributes"]["port"] = 443
    assert resolved.aliases == ["web01"]
    assert resolved.attributes == {"port": 22}


def test_resolution_record_to_dict_serializes_plain_values_and_copies_mutables():
    record = _record()

    data = record.to_dict()

    assert data["resolution_confidence"] == "HIGH"
    data["supporting_entities"].append("mutated")
    assert record.supporting_entities == ["ent-1", "ent-2"]


def test_public_api_exports_identity_resolution_subsystem():
    assert IdentityResolver is not None
    assert ResolutionMethod.EXACT_IP.value == "EXACT_IP"
    assert ResolutionConfidence.UNKNOWN.value == "UNKNOWN"


def test_stable_resolved_entity_id_is_deterministic_and_type_scoped():
    host_id = stable_resolved_entity_id(EntityType.HOST, "10.0.0.5")

    assert host_id == stable_resolved_entity_id(EntityType.HOST, "10.0.0.5")
    assert host_id != stable_resolved_entity_id(EntityType.USER, "10.0.0.5")


def test_validate_resolution_record_accepts_valid_record():
    record = _record()

    validate_resolution_record(record)

    assert is_valid_resolution_record(record) is True


@pytest.mark.parametrize(
    "field_name", ("resolution_reason", "timestamp", "resolver_version")
)
def test_validate_resolution_record_rejects_blank_required_strings(field_name):
    record = _record(**{field_name: "   "})

    assert is_valid_resolution_record(record) is False
    with pytest.raises(ResolutionValidationError, match=field_name):
        validate_resolution_record(record)


def test_validate_resolution_record_rejects_invalid_method():
    record = _record(resolution_method="EXACT_IDENTIFIER")

    with pytest.raises(ResolutionValidationError, match="resolution_method"):
        validate_resolution_record(record)


def test_validate_resolution_record_rejects_invalid_confidence():
    record = _record(resolution_confidence="HIGH")

    with pytest.raises(ResolutionValidationError, match="resolution_confidence"):
        validate_resolution_record(record)


def test_validate_resolved_entity_accepts_valid_entity():
    resolved = _resolved()

    validate_resolved_entity(resolved)

    assert is_valid_resolved_entity(resolved) is True


@pytest.mark.parametrize("field_name", ("id", "primary_identifier"))
def test_validate_resolved_entity_rejects_blank_required_strings(field_name):
    resolved = _resolved(**{field_name: "   "})

    assert is_valid_resolved_entity(resolved) is False
    with pytest.raises(ResolutionValidationError, match=field_name):
        validate_resolved_entity(resolved)


def test_validate_resolved_entity_rejects_duplicate_sources_and_aliases():
    resolved = _resolved(aliases=["web01", "web01"])

    with pytest.raises(ResolutionValidationError, match="duplicates"):
        validate_resolved_entity(resolved)


def test_validate_resolved_entity_rejects_alias_equal_to_primary_identifier():
    resolved = _resolved(aliases=["10.0.0.5"])

    with pytest.raises(ResolutionValidationError, match="primary_identifier"):
        validate_resolved_entity(resolved)


def test_exact_identifier_matching_merges_and_records_method():
    entities = [
        _entity(id="ent-1", source_finding="finding-1"),
        _entity(id="ent-2", source_finding="finding-2", attributes={"os": "linux"}),
    ]

    resolved = IdentityResolver.resolve(entities)

    assert len(resolved) == 1
    assert resolved[0].source_entities == ["ent-1", "ent-2"]
    assert resolved[0].source_findings == ["finding-1", "finding-2"]
    assert resolved[0].attributes == {"port": 22, "os": "linux"}
    assert resolved[0].resolution_records[0].resolution_method is ResolutionMethod.EXACT_IDENTIFIER
    assert resolved[0].resolution_records[0].resolution_confidence is ResolutionConfidence.HIGH


def test_alias_matching_merges_when_primary_matches_existing_alias():
    entities = [
        _entity(id="ent-1", primary_identifier="10.0.0.5", aliases=["web01"]),
        _entity(id="ent-2", primary_identifier="web01", aliases=[]),
    ]

    resolved = IdentityResolver.resolve(entities)

    assert len(resolved) == 1
    assert resolved[0].resolution_records[0].resolution_method is ResolutionMethod.EXACT_ALIAS


def test_alias_matching_merges_when_alias_matches_existing_primary():
    entities = [
        _entity(id="ent-1", primary_identifier="10.0.0.5"),
        _entity(id="ent-2", primary_identifier="web01", aliases=["10.0.0.5"]),
    ]

    resolved = IdentityResolver.resolve(entities)

    assert len(resolved) == 1
    assert resolved[0].resolution_records[0].resolution_method is ResolutionMethod.EXACT_ALIAS


def test_exact_ip_matching_normalizes_ip_without_modifying_entity():
    entity = _entity(id="ent-1", primary_identifier="2001:0db8:0:0:0:0:0:1")
    same_ip = _entity(id="ent-2", primary_identifier="2001:db8::1")

    resolved = IdentityResolver.resolve([entity, same_ip])

    assert len(resolved) == 1
    assert resolved[0].resolution_records[0].resolution_method is ResolutionMethod.EXACT_IP
    assert entity.primary_identifier == "2001:0db8:0:0:0:0:0:1"


def test_exact_hostname_matching_is_case_insensitive_for_hosts():
    entities = [
        _entity(id="ent-1", primary_identifier="WEB01"),
        _entity(id="ent-2", primary_identifier="web01"),
    ]

    resolved = IdentityResolver.resolve(entities)

    assert len(resolved) == 1
    assert resolved[0].resolution_records[0].resolution_method is ResolutionMethod.EXACT_HOSTNAME


def test_conflicting_entity_types_are_not_merged():
    entities = [
        _entity(id="host-1", type=EntityType.HOST, primary_identifier="admin"),
        _entity(id="user-1", type=EntityType.USER, primary_identifier="admin"),
    ]

    resolved = IdentityResolver.resolve(entities)

    assert len(resolved) == 2


def test_no_deterministic_proof_keeps_entities_separate():
    entities = [
        _entity(id="ent-1", primary_identifier="10.0.0.5"),
        _entity(id="ent-2", primary_identifier="10.0.0.6"),
    ]

    resolved = IdentityResolver.resolve(entities)

    assert len(resolved) == 2
    assert all(not item.resolution_records for item in resolved)


def test_duplicate_prevention_for_source_lists_and_aliases():
    entities = [
        _entity(id="ent-1", aliases=["web01"], source_finding="finding-1"),
        _entity(id="ent-1", aliases=["web01"], source_finding="finding-1"),
    ]

    resolved = IdentityResolver.resolve(entities)

    assert resolved[0].source_entities == ["ent-1"]
    assert resolved[0].source_findings == ["finding-1"]
    assert resolved[0].aliases == ["web01"]


def test_resolve_output_grouping_is_deterministic_for_input_order():
    entities = [
        _entity(id="ent-2", primary_identifier="10.0.0.6"),
        _entity(id="ent-1", primary_identifier="10.0.0.5"),
    ]

    first = [item.id for item in IdentityResolver.resolve(entities)]
    second = [item.id for item in IdentityResolver.resolve(list(reversed(entities)))]

    assert first == second


def test_resolve_empty_input_returns_empty_list():
    assert IdentityResolver.resolve([]) == []


def test_resolve_rejects_invalid_entity_input():
    entity = _entity(id="   ")

    with pytest.raises(EntityValidationError):
        IdentityResolver.resolve([entity])


def test_resolve_rejects_non_entity_input():
    with pytest.raises(EntityValidationError):
        IdentityResolver.resolve(["not-an-entity"])


def test_resolver_does_not_modify_input_entities():
    entity = _entity(aliases=["web01"], attributes={"port": 22})
    before = entity.to_dict()

    IdentityResolver.resolve([entity, _entity(id="ent-2")])

    assert entity.to_dict() == before
