# ─────────────────────────────────────────────────────────────────────────────
# tests/test_findings.py
# ─────────────────────────────────────────────────────────────────────────────
"""
Tests for the Milestone 1 finding subsystem.

Coverage
--------
- Finding.to_dict() round-trip
- EntityType field (new in this iteration)
- Stable / deterministic ID generation
- Schema validation: valid findings, empty strings, bad enum values,
  blank optional strings, wrong collection types
- Finding Builder: success path, invalid enum, batch processing,
  auto-ID vs. explicit-ID, entity_type coercion
- Example module contract shape and backward compatibility

All tests are plain functions (pytest-compatible, no dependencies
beyond the stdlib and the thragg package itself).
"""

import hashlib

import pytest

from thragg.core.foundation.finding import Confidence, EntityType, Finding, Severity
from thragg.core.foundation.finding_builder import (
    build_finding,
    build_findings_from_rule_results,
    _generate_id,
)
from thragg.core.foundation.finding_schema import (
    FindingValidationError,
    is_valid_finding,
    validate_finding,
)
from thragg.modules.example_nmap.module import run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_finding(**overrides) -> Finding:
    """Return the smallest valid Finding, with optional field overrides."""
    defaults = dict(
        id            = "X-001",
        title         = "Test Finding",
        description   = "A description.",
        severity      = Severity.LOW,
        confidence    = Confidence.LOW,
        category      = "Test",
        type          = "TEST_TYPE",
        source_module = "test_module",
        source_rule   = "TEST-RULE-001",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _minimal_rule_result(**overrides) -> dict:
    """Return the smallest valid rule-result dict."""
    defaults = dict(
        title         = "Finding",
        description   = "desc",
        severity      = "LOW",
        confidence    = "LOW",
        category      = "Cat",
        type          = "TYPE_X",
        source_rule   = "R1",
    )
    defaults.update(overrides)
    return defaults


# ---------------------------------------------------------------------------
# Finding model — to_dict round-trip
# ---------------------------------------------------------------------------

class TestFindingToDict:

    def test_roundtrip_preserves_all_fields(self):
        f = _minimal_finding(
            entity_type  = EntityType.HOST,
            asset        = "10.0.0.1",
            observed_at  = "2026-07-01T00:00:00Z",
            mitre        = ["T1021.004"],
            tags         = ["ssh"],
            evidence     = {"port": 22},
            recommendation = "Fix it.",
        )
        d = f.to_dict()

        assert d["id"]             == "X-001"
        assert d["title"]          == "Test Finding"
        assert d["severity"]       == "LOW"
        assert d["confidence"]     == "LOW"
        assert d["entity_type"]    == "HOST"
        assert d["asset"]          == "10.0.0.1"
        assert d["observed_at"]    == "2026-07-01T00:00:00Z"
        assert d["mitre"]          == ["T1021.004"]
        assert d["tags"]           == ["ssh"]
        assert d["evidence"]       == {"port": 22}
        assert d["recommendation"] == "Fix it."
        assert d["source_module"]  == "test_module"
        assert d["source_rule"]    == "TEST-RULE-001"

    def test_enums_serialized_as_strings(self):
        f = _minimal_finding(
            severity    = Severity.CRITICAL,
            confidence  = Confidence.HIGH,
            entity_type = EntityType.USER,
        )
        d = f.to_dict()
        assert d["severity"]    == "CRITICAL"
        assert d["confidence"]  == "HIGH"
        assert d["entity_type"] == "USER"

    def test_optional_none_fields_present_in_dict(self):
        f = _minimal_finding()
        d = f.to_dict()
        assert d["asset"]          is None
        assert d["observed_at"]    is None
        assert d["recommendation"] is None

    def test_collections_are_copies(self):
        mitre = ["T1021"]
        tags  = ["a"]
        evid  = {"k": "v"}
        f = _minimal_finding(mitre=mitre, tags=tags, evidence=evid)
        d = f.to_dict()

        # Mutating the returned dict must not affect the Finding.
        d["mitre"].append("X")
        d["tags"].append("b")
        d["evidence"]["new"] = 1

        assert f.mitre    == ["T1021"]
        assert f.tags     == ["a"]
        assert f.evidence == {"k": "v"}

    def test_entity_type_defaults_to_unknown(self):
        f = _minimal_finding()
        assert f.entity_type           == EntityType.UNKNOWN
        assert f.to_dict()["entity_type"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# EntityType enum
# ---------------------------------------------------------------------------

class TestEntityType:

    def test_all_expected_members_present(self):
        expected = {
            "HOST", "USER", "SERVICE", "APPLICATION", "IP_ADDRESS",
            "PORT", "CONTAINER", "NETWORK", "STORAGE", "DATABASE",
            "CLOUD_RESOURCE", "IDENTITY", "PROCESS", "FILE",
            "REGISTRY_KEY", "DOMAIN", "CERTIFICATE", "UNKNOWN",
        }
        actual = {e.value for e in EntityType}
        assert expected == actual

    def test_string_inheritance(self):
        # EntityType members should compare equal to their string value.
        assert EntityType.HOST == "HOST"
        assert EntityType.USER == "USER"


# ---------------------------------------------------------------------------
# Stable / deterministic ID generation
# ---------------------------------------------------------------------------

class TestGenerateId:

    def test_same_inputs_produce_same_id(self):
        id1 = _generate_id("nmap", "RULE-001", "10.0.0.1")
        id2 = _generate_id("nmap", "RULE-001", "10.0.0.1")
        assert id1 == id2

    def test_different_asset_produces_different_id(self):
        id1 = _generate_id("nmap", "RULE-001", "10.0.0.1")
        id2 = _generate_id("nmap", "RULE-001", "10.0.0.2")
        assert id1 != id2

    def test_different_rule_produces_different_id(self):
        id1 = _generate_id("nmap", "RULE-001", "host")
        id2 = _generate_id("nmap", "RULE-002", "host")
        assert id1 != id2

    def test_different_module_produces_different_id(self):
        id1 = _generate_id("nmap",  "RULE-001", "host")
        id2 = _generate_id("cloud", "RULE-001", "host")
        assert id1 != id2

    def test_none_asset_handled(self):
        id1 = _generate_id("nmap", "RULE-001", None)
        id2 = _generate_id("nmap", "RULE-001", None)
        assert id1 == id2

    def test_id_prefixed_with_module_name(self):
        result = _generate_id("logs", "RULE-001", "host")
        assert result.startswith("logs-")

    def test_id_length_is_predictable(self):
        # "logs-" (5) + 16 hex chars = 21 chars total.
        result = _generate_id("logs", "RULE-001", "host")
        module_prefix_len = len("logs-")
        assert len(result) == module_prefix_len + 16

    def test_hash_correctness(self):
        raw    = "nmap|RULE-001|10.0.0.1"
        digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
        assert _generate_id("nmap", "RULE-001", "10.0.0.1") == f"nmap-{digest}"


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

class TestValidateFinding:

    def test_accepts_minimal_valid_finding(self):
        f = _minimal_finding()
        validate_finding(f)          # must not raise
        assert is_valid_finding(f) is True

    def test_accepts_fully_populated_finding(self):
        f = _minimal_finding(
            entity_type    = EntityType.SERVICE,
            asset          = "svc-001",
            observed_at    = "2026-01-01T00:00:00Z",
            mitre          = ["T1078"],
            tags           = ["auth"],
            evidence       = {"key": "val"},
            recommendation = "Patch it.",
        )
        validate_finding(f)

    # ── Required string fields ─────────────────────────────────────────────

    @pytest.mark.parametrize("field_name", [
        "id", "title", "description", "category",
        "type", "source_module", "source_rule",
    ])
    def test_rejects_empty_required_string(self, field_name):
        f = _minimal_finding(**{field_name: ""})
        assert is_valid_finding(f) is False
        with pytest.raises(FindingValidationError, match=field_name):
            validate_finding(f)

    @pytest.mark.parametrize("field_name", [
        "id", "title", "description", "category",
        "type", "source_module", "source_rule",
    ])
    def test_rejects_whitespace_only_required_string(self, field_name):
        f = _minimal_finding(**{field_name: "   "})
        assert is_valid_finding(f) is False

    @pytest.mark.parametrize("field_name", [
        "id", "title", "description", "category",
        "type", "source_module", "source_rule",
    ])
    def test_rejects_none_required_string(self, field_name):
        f = _minimal_finding(**{field_name: None})
        assert is_valid_finding(f) is False

    # ── Enum fields ────────────────────────────────────────────────────────

    def test_rejects_raw_string_severity(self):
        f = _minimal_finding(severity="HIGH")      # str, not Severity
        assert is_valid_finding(f) is False
        with pytest.raises(FindingValidationError, match="severity"):
            validate_finding(f)

    def test_rejects_raw_string_confidence(self):
        f = _minimal_finding(confidence="LOW")
        assert is_valid_finding(f) is False

    def test_rejects_raw_string_entity_type(self):
        f = _minimal_finding(entity_type="HOST")   # str, not EntityType
        assert is_valid_finding(f) is False
        with pytest.raises(FindingValidationError, match="entity_type"):
            validate_finding(f)

    def test_error_message_lists_valid_entity_types(self):
        f = _minimal_finding(entity_type="ROBOT")
        with pytest.raises(FindingValidationError) as exc_info:
            validate_finding(f)
        msg = str(exc_info.value)
        assert "HOST" in msg
        assert "USER" in msg

    # ── Optional fields: blank strings rejected ────────────────────────────

    def test_rejects_blank_asset_string(self):
        f = _minimal_finding(asset="   ")
        assert is_valid_finding(f) is False
        with pytest.raises(FindingValidationError, match="asset"):
            validate_finding(f)

    def test_rejects_blank_observed_at_string(self):
        f = _minimal_finding(observed_at="  ")
        assert is_valid_finding(f) is False

    def test_accepts_none_asset(self):
        f = _minimal_finding(asset=None)
        assert is_valid_finding(f) is True

    def test_accepts_none_observed_at(self):
        f = _minimal_finding(observed_at=None)
        assert is_valid_finding(f) is True

    def test_rejects_non_string_asset(self):
        f = _minimal_finding(asset=42)
        assert is_valid_finding(f) is False

    # ── Collection fields ──────────────────────────────────────────────────

    def test_rejects_non_list_mitre(self):
        f = _minimal_finding(mitre="T1078")
        assert is_valid_finding(f) is False

    def test_rejects_mitre_with_non_string_element(self):
        f = _minimal_finding(mitre=[1234])
        assert is_valid_finding(f) is False

    def test_rejects_non_list_tags(self):
        f = _minimal_finding(tags="tag")
        assert is_valid_finding(f) is False

    def test_rejects_non_dict_evidence(self):
        f = _minimal_finding(evidence=["a", "b"])
        assert is_valid_finding(f) is False

    def test_accepts_empty_collections(self):
        f = _minimal_finding(mitre=[], tags=[], evidence={})
        assert is_valid_finding(f) is True


# ---------------------------------------------------------------------------
# Finding Builder — build_finding
# ---------------------------------------------------------------------------

class TestBuildFinding:

    def test_success_path_returns_finding(self):
        f = build_finding(
            title         = "Brute Force",
            description   = "Many failures",
            severity      = "HIGH",
            confidence    = "MEDIUM",
            category      = "Authentication",
            type          = "FAILED_LOGIN",
            source_module = "logs",
            source_rule   = "LOG-BRUTE-001",
        )
        assert f is not None
        assert isinstance(f, Finding)
        assert f.severity   == Severity.HIGH
        assert f.confidence == Confidence.MEDIUM

    def test_coerces_lowercase_severity(self):
        f = build_finding(
            title="t", description="d", severity="critical",
            confidence="low", category="c", type="T",
            source_module="m", source_rule="r",
        )
        assert f is not None
        assert f.severity == Severity.CRITICAL

    def test_invalid_severity_returns_none(self):
        f = build_finding(
            title="t", description="d", severity="NOT_A_LEVEL",
            confidence="LOW", category="c", type="T",
            source_module="logs", source_rule="R1",
        )
        assert f is None

    def test_invalid_confidence_returns_none(self):
        f = build_finding(
            title="t", description="d", severity="LOW",
            confidence="VERY_SURE", category="c", type="T",
            source_module="logs", source_rule="R1",
        )
        assert f is None

    def test_entity_type_coercion_from_string(self):
        f = build_finding(
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="m", source_rule="r",
            entity_type="HOST",
        )
        assert f is not None
        assert f.entity_type == EntityType.HOST

    def test_entity_type_defaults_to_unknown_when_omitted(self):
        f = build_finding(
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="m", source_rule="r",
        )
        assert f is not None
        assert f.entity_type == EntityType.UNKNOWN

    def test_entity_type_defaults_to_unknown_when_none(self):
        f = build_finding(
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="m", source_rule="r",
            entity_type=None,
        )
        assert f is not None
        assert f.entity_type == EntityType.UNKNOWN

    def test_invalid_entity_type_returns_none(self):
        f = build_finding(
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="m", source_rule="r",
            entity_type="ROBOT",
        )
        assert f is None

    # ── ID handling ────────────────────────────────────────────────────────

    def test_explicit_id_is_preserved(self):
        f = build_finding(
            id="MY-EXPLICIT-ID",
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="m", source_rule="r",
        )
        assert f is not None
        assert f.id == "MY-EXPLICIT-ID"

    def test_auto_id_generated_when_id_omitted(self):
        f = build_finding(
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="nmap", source_rule="R1", asset="10.0.0.1",
        )
        assert f is not None
        expected = _generate_id("nmap", "R1", "10.0.0.1")
        assert f.id == expected

    def test_auto_id_is_stable_across_calls(self):
        kwargs = dict(
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="logs", source_rule="RULE", asset="host-1",
        )
        f1 = build_finding(**kwargs)
        f2 = build_finding(**kwargs)
        assert f1 is not None and f2 is not None
        assert f1.id == f2.id

    def test_auto_id_differs_for_different_assets(self):
        base = dict(
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="logs", source_rule="RULE",
        )
        f1 = build_finding(**base, asset="host-1")
        f2 = build_finding(**base, asset="host-2")
        assert f1 is not None and f2 is not None
        assert f1.id != f2.id

    def test_empty_string_id_triggers_auto_generation(self):
        f = build_finding(
            id="",
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="nmap", source_rule="R1", asset="h",
        )
        assert f is not None
        expected = _generate_id("nmap", "R1", "h")
        assert f.id == expected

    # ── Optional fields ────────────────────────────────────────────────────

    def test_none_optional_fields_accepted(self):
        f = build_finding(
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="m", source_rule="r",
            asset=None, observed_at=None, recommendation=None,
        )
        assert f is not None

    def test_empty_collections_accepted(self):
        f = build_finding(
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="m", source_rule="r",
            mitre=[], tags=[], evidence={},
        )
        assert f is not None
        assert f.mitre    == []
        assert f.tags     == []
        assert f.evidence == {}

    def test_collections_are_copied(self):
        mitre = ["T1078"]
        tags  = ["auth"]
        evid  = {"k": "v"}
        f = build_finding(
            title="t", description="d", severity="LOW",
            confidence="LOW", category="c", type="T",
            source_module="m", source_rule="r",
            mitre=mitre, tags=tags, evidence=evid,
        )
        assert f is not None
        mitre.append("extra")
        tags.append("extra")
        evid["new"] = 1
        assert f.mitre    == ["T1078"]
        assert f.tags     == ["auth"]
        assert f.evidence == {"k": "v"}


# ---------------------------------------------------------------------------
# Finding Builder — batch helper
# ---------------------------------------------------------------------------

class TestBuildFindingsFromRuleResults:

    def test_empty_list_returns_empty_list(self):
        assert build_findings_from_rule_results([], source_module="logs") == []

    def test_all_valid_entries_returned(self):
        results = [
            _minimal_rule_result(id="R-001", source_rule="R1"),
            _minimal_rule_result(id="R-002", source_rule="R2"),
        ]
        findings = build_findings_from_rule_results(results, source_module="logs")
        assert len(findings) == 2

    def test_bad_entry_skipped_others_kept(self):
        results = [
            _minimal_rule_result(id="OK-001", source_rule="R1"),
            _minimal_rule_result(id="BAD-001", severity="INVALID", source_rule="R2"),
            _minimal_rule_result(id="OK-002", source_rule="R3"),
        ]
        findings = build_findings_from_rule_results(results, source_module="logs")
        assert len(findings) == 2
        ids = [f.id for f in findings]
        assert "OK-001" in ids
        assert "OK-002" in ids

    def test_all_bad_entries_returns_empty_list(self):
        results = [
            _minimal_rule_result(severity="BOGUS", source_rule="R1"),
            _minimal_rule_result(severity="BOGUS", source_rule="R2"),
        ]
        findings = build_findings_from_rule_results(results, source_module="logs")
        assert findings == []

    def test_source_module_injected_correctly(self):
        results = [_minimal_rule_result(id="X-001", source_rule="R1")]
        findings = build_findings_from_rule_results(results, source_module="cloud")
        assert findings[0].source_module == "cloud"

    def test_entity_type_in_batch(self):
        results = [
            _minimal_rule_result(id="H-001", source_rule="R1", entity_type="HOST"),
            _minimal_rule_result(id="U-001", source_rule="R2", entity_type="USER"),
        ]
        findings = build_findings_from_rule_results(results, source_module="m")
        types = {f.entity_type for f in findings}
        assert EntityType.HOST in types
        assert EntityType.USER in types


# ---------------------------------------------------------------------------
# Example module — contract and backward compatibility
# ---------------------------------------------------------------------------

class TestExampleModule:

    def _one_host_scan(self, port: int = 22, state: str = "open") -> dict:
        return {
            "hosts": [
                {
                    "ip":    "10.0.0.5",
                    "ports": [{"number": port, "state": state}],
                }
            ]
        }

    def test_contract_has_all_expected_fields(self):
        contract = run(self._one_host_scan(), observed_at="2026-07-01T00:00:00Z")
        for field in ("metadata", "summary", "findings", "details", "artifacts", "errors"):
            assert field in contract

    def test_one_ssh_host_produces_one_finding(self):
        contract = run(self._one_host_scan(), observed_at="2026-07-01T00:00:00Z")
        assert len(contract["findings"]) == 1

    def test_finding_entity_type_is_host(self):
        contract  = run(self._one_host_scan(), observed_at="2026-07-01T00:00:00Z")
        finding   = contract["findings"][0]
        assert finding["entity_type"] == "HOST"

    def test_finding_type_is_ssh_exposed(self):
        contract = run(self._one_host_scan(), observed_at="2026-07-01T00:00:00Z")
        assert contract["findings"][0]["type"] == "SSH_EXPOSED"

    def test_no_ssh_produces_empty_findings(self):
        contract = run(self._one_host_scan(port=443))
        assert contract["findings"] == []

    def test_closed_ssh_produces_empty_findings(self):
        contract = run(self._one_host_scan(port=22, state="closed"))
        assert contract["findings"] == []

    def test_observed_at_none_accepted(self):
        contract = run(self._one_host_scan())
        assert len(contract["findings"]) == 1
        assert contract["findings"][0]["observed_at"] is None

    def test_backward_compat_legacy_fields_present(self):
        """Existing contract fields must not be removed or renamed."""
        contract = run(self._one_host_scan())
        assert "metadata" in contract
        assert "summary"  in contract
        assert "details"  in contract
        assert "artifacts" in contract
        assert "errors"   in contract

    def test_multiple_ssh_hosts_produce_multiple_findings(self):
        scan = {
            "hosts": [
                {"ip": "10.0.0.1", "ports": [{"number": 22, "state": "open"}]},
                {"ip": "10.0.0.2", "ports": [{"number": 22, "state": "open"}]},
                {"ip": "10.0.0.3", "ports": [{"number": 443, "state": "open"}]},
            ]
        }
        contract = run(scan)
        assert len(contract["findings"]) == 2

    def test_finding_ids_are_stable_across_runs(self):
        scan     = self._one_host_scan()
        contract1 = run(scan, observed_at="2026-07-01T00:00:00Z")
        contract2 = run(scan, observed_at="2026-07-01T00:00:00Z")
        assert contract1["findings"][0]["id"] == contract2["findings"][0]["id"]
