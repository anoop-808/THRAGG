"""Minimal example Nmap module for finding and entity contract tests."""

from __future__ import annotations

from typing import Any

from core.entity_extractor import EntityExtractor
from core.finding import EntityType
from core.finding_builder import build_finding


def run(scan: dict[str, Any], observed_at: str | None = None) -> dict[str, Any]:
    """Return findings for open SSH services in a parsed scan dict."""
    findings = []
    for host in scan.get("hosts", []):
        ip = host.get("ip")
        for port in host.get("ports", []):
            if port.get("number") != 22 or port.get("state") != "open":
                continue
            finding = build_finding(
                title="SSH Service Exposed",
                description=f"SSH open on {ip}",
                severity="MEDIUM",
                confidence="HIGH",
                category="Network Exposure",
                type="SSH_EXPOSED",
                source_module="example_nmap",
                source_rule="NMAP-SSH-EXPOSED-001",
                entity_type=EntityType.HOST,
                asset=ip,
                observed_at=observed_at,
                evidence={"ip": ip, "port": 22},
                recommendation="Restrict SSH exposure.",
            )
            if finding is not None:
                findings.append(finding)

    entities = EntityExtractor.extract_batch(findings)
    return {
        "metadata": {"module": "example_nmap"},
        "summary": {"total_findings": len(findings)},
        "findings": [finding.to_dict() for finding in findings],
        "entities": [entity.to_dict() for entity in entities],
        "details": {},
        "artifacts": {},
        "errors": [],
    }
