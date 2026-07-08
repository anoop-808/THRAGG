"""
core.correlation_engine
=======================

Milestone 5 orchestration layer.
"""

from __future__ import annotations

from typing import Any

from .correlation import Correlation
from .correlation_builder import CorrelationBuilder
from .correlation_repository import CorrelationRepository
from .correlation_rule import CorrelationRule
from ..foundation.entity_extractor import EntityExtractor
from ..foundation.entity_registry import EntityRegistry
from ..foundation.finding import EntityType, Finding
from ..foundation.finding_builder import build_finding
from ..foundation.knowledge_base import KnowledgeBase
from .pattern_evaluator import PatternEvaluator
from ..foundation.relationship_graph import RelationshipGraph
from ..foundation.relationship_inference import RelationshipInferencer
from ..foundation.relationship_repository import RelationshipRepository
from ..foundation.resolved_entity import ResolvedEntity

__all__ = ["CorrelationEngine"]


class CorrelationEngine:
    """Evaluate registered rules and store non-duplicate correlations."""

    def __init__(
        self,
        rules: tuple[CorrelationRule, ...],
        evaluator: PatternEvaluator | None = None,
        builder: CorrelationBuilder | None = None,
        repository: CorrelationRepository | None = None,
        entity_registry: EntityRegistry | None = None,
        relationship_repository: RelationshipRepository | None = None,
        inferencer: RelationshipInferencer | None = None,
    ) -> None:
        self.rules = rules
        self.evaluator = evaluator or PatternEvaluator()
        self.builder = builder or CorrelationBuilder()
        self.repository = repository or CorrelationRepository()
        self.entity_registry = entity_registry or EntityRegistry()
        self.relationship_repository = (
            relationship_repository or RelationshipRepository()
        )
        self.inferencer = inferencer or RelationshipInferencer()
        self.graph = RelationshipGraph()

    def run(
        self,
        knowledge_base: KnowledgeBase,
        resolved_entities: dict[str, ResolvedEntity] | None = None,
    ) -> tuple[Correlation, ...]:
        """Evaluate all rules and return stored correlations."""
        if not isinstance(knowledge_base, KnowledgeBase):
            raise TypeError("knowledge_base must be a KnowledgeBase")
        if resolved_entities is not None and not isinstance(resolved_entities, dict):
            raise TypeError("resolved_entities must be a dict or None")
        for rule in self.rules:
            for match in self.evaluator.evaluate(rule, knowledge_base, resolved_entities):
                self.repository.add(self.builder.build(rule, match))
        return self.repository.list()

    def run_contracts(
        self, contracts: tuple[dict[str, Any], ...]
    ) -> tuple[Correlation, ...]:
        """Build the correlation foundation from validated THRAGG contracts."""
        if not isinstance(contracts, (tuple, list)):
            raise TypeError("contracts must be a tuple or list of THRAGG contracts")
        findings = self._findings_from_contracts(contracts)
        extracted = EntityExtractor.extract_batch(list(findings))
        resolved = self.entity_registry.register(extracted)
        relationships = self.inferencer.infer(findings, resolved)
        self.relationship_repository.add_many(relationships)
        self.graph = self.relationship_repository.knowledge_base.build_graph()
        return self.run(
            self.relationship_repository.knowledge_base,
            self.entity_registry.repository.as_dict(),
        )

    @staticmethod
    def _findings_from_contracts(
        contracts: tuple[dict[str, Any], ...]
    ) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        for contract in contracts:
            CorrelationEngine._validate_contract(contract)
            metadata = contract["metadata"]
            source_module = str(
                metadata.get("module") or metadata.get("tool") or "unknown"
            )
            for category_list in contract["details"].values():
                if isinstance(category_list, list):
                    for raw in category_list:
                        finding = CorrelationEngine._coerce_finding(raw, source_module)
                        if finding is not None:
                            findings.append(finding)
        return tuple(findings)

    @staticmethod
    def _validate_contract(contract: dict[str, Any]) -> None:
        if not isinstance(contract, dict):
            raise TypeError("Invalid THRAGG contract; contract must be a dict")
        required = ("metadata", "summary", "details", "artifacts", "errors")
        missing = [key for key in required if key not in contract]
        if missing:
            raise ValueError(f"Invalid THRAGG contract; missing {missing}")
        expected_types = {
            "metadata": dict,
            "summary": dict,
            "details": dict,
            "artifacts": dict,
            "errors": list,
        }
        for key, expected_type in expected_types.items():
            if not isinstance(contract[key], expected_type):
                raise TypeError(
                    "Invalid THRAGG contract; "
                    f"{key} must be {expected_type.__name__}"
                )
        if not isinstance(contract["details"].get("findings", []), list):
            raise ValueError("Invalid THRAGG contract; details.findings must be a list")

    @staticmethod
    def _coerce_finding(raw: Any, source_module: str) -> Finding:
        if isinstance(raw, Finding):
            return raw
        if not isinstance(raw, dict):
            raise TypeError(
                "Invalid THRAGG contract; details.findings entries must be dicts "
                "or Finding objects"
            )
        evidence = dict(raw.get("evidence") or {})
        if raw.get("subscription_id"):
            raw["asset"] = raw.get("subscription_id")
            raw["entity_type"] = "CLOUD_RESOURCE"
            evidence["subscription"] = raw.get("subscription_id")
            user_name = raw.get("raw", {}).get("user", {}).get("name")
            if user_name:
                evidence["upn"] = user_name
                evidence["username"] = user_name

        for key in (
            "asset",
            "host",
            "hostname",
            "ip",
            "ip_address",
            "user",
            "username",
            "service",
            "service_name",
            "port",
            "protocol",
            "cloud_resource",
            "subscription",
            "object_id",
            "upn",
        ):
            if key in raw and raw[key] not in (None, ""):
                evidence.setdefault(key, raw[key])
        return build_finding(
            id=str(raw.get("id") or raw.get("rule_id") or ""),
            title=str(raw.get("title") or raw.get("rule_id") or "Untitled finding"),
            description=str(
                raw.get("description") or raw.get("title") or "No description."
            ),
            severity=CorrelationEngine._severity(raw.get("severity")),
            confidence=CorrelationEngine._confidence(raw.get("confidence")),
            category=str(raw.get("category") or "Correlation Input"),
            type=str(raw.get("type") or raw.get("rule_id") or "FINDING"),
            source_module=source_module,
            source_rule=str(raw.get("source_rule") or raw.get("rule_id") or "unknown"),
            entity_type=CorrelationEngine._entity_type(raw, evidence),
            asset=raw.get("asset"),
            observed_at=raw.get("observed_at") or raw.get("timestamp"),
            mitre=CorrelationEngine._mitre(raw.get("mitre")),
            tags=list(raw.get("tags") or ()),
            evidence=evidence,
            recommendation=raw.get("recommendation"),
        )

    @staticmethod
    def _severity(value: Any) -> str:
        text = str(value or "LOW").upper()
        return "LOW" if text == "INFORMATIONAL" else text

    @staticmethod
    def _confidence(value: Any) -> str:
        text = str(value or "MEDIUM").upper()
        return "HIGH" if text == "CONFIRMED" else text

    @staticmethod
    def _entity_type(raw: dict[str, Any], evidence: dict[str, Any]) -> EntityType:
        if raw.get("entity_type"):
            try:
                return EntityType(str(raw["entity_type"]).upper())
            except ValueError:
                return EntityType.UNKNOWN
        if evidence.get("upn") or evidence.get("object_id"):
            return EntityType.IDENTITY
        if raw.get("asset") or evidence.get("ip") or evidence.get("ip_address"):
            return EntityType.HOST
        if evidence.get("user") or evidence.get("username"):
            return EntityType.USER
        if evidence.get("service") or evidence.get("service_name"):
            return EntityType.SERVICE
        return EntityType.UNKNOWN

    @staticmethod
    def _mitre(value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item) for item in value]
        if isinstance(value, dict) and value.get("technique_id"):
            return [str(value["technique_id"])]
        return []
