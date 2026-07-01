"""THRAGG base.py
Shared utilities, metadata builders, risk/confidence engines, finding normalization.
No security rules. Provides 'how', not 'what'.
"""

from __future__ import annotations

import os
import json
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional, Any

# ═══════════════════════════════════════════════════════════════════════════════
# Metadata Building
# ═══════════════════════════════════════════════════════════════════════════════

def build_metadata(module_name: str, module_version: str, tool_name: str, input_path: str) -> Dict:
    """Build standard THRAGG metadata dict."""
    return {
        "module": module_name,
        "module_version": module_version,
        "tool": tool_name,
        "input_path": input_path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_time": None,
        "files_processed": 0,
        "folders_processed": 0,
        "pipeline": [],
        "processing_stats": {},
        "module_health": {},
        "rule_statistics": {},
    }


def finalize_metadata(
    metadata: Dict,
    elapsed_time: float,
    pipeline: Pipeline,
) -> Dict:
    """Finalize metadata: add execution_time, pipeline."""
    metadata["execution_time"] = round(elapsed_time, 4)
    metadata["pipeline"] = pipeline.to_list()
    return metadata


# ═══════════════════════════════════════════════════════════════════════════════
# Scoring Tables (Severity, Confidence, Asset Exposure, Exploitability)
# ═══════════════════════════════════════════════════════════════════════════════

SEVERITY_WEIGHT = {
    "Critical": 100,
    "High": 80,
    "Medium": 50,
    "Low": 25,
    "Informational": 5,
}

CONFIDENCE_SCORE = {
    "Confirmed": (100, 1.00),
    "High": (80, 0.90),
    "Medium": (60, 0.70),
    "Low": (40, 0.50),
}

# Renamed from EXPOSURE to ASSET_EXPOSURE.
# Represents how exposed an asset type is relative to blast radius.
# v2: extend with vm, storage, keyvault, nsg, public_ip, subscription
# for cloud.py coverage.
ASSET_EXPOSURE = {
    "tenant": 1.0,
    "application": 0.9,
    "user": 0.8,
    "group": 0.7,
    "hygiene": 0.6,
}

EXPLOITABILITY = {
    "trivial": 1.0,
    "moderate": 0.7,
    "contextual": 0.5,
}


# ═══════════════════════════════════════════════════════════════════════════════
# Confidence Scoring
# ═══════════════════════════════════════════════════════════════════════════════

def confidence_from_score(score: int) -> str:
    """Convert numeric confidence score (0-100) to label."""
    if score >= 90:
        return "Confirmed"
    if score >= 70:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def compute_confidence(
    signal_type: str,
    signals: Optional[Dict[str, bool]] = None,
) -> Tuple[str, int, str]:
    """
    Compute confidence label from signal type and optional modifiers.

    Returns:
        (confidence_label, confidence_score, confidence_rationale)
    """
    signals = signals or {}

    base_scores = {
        # Deterministic — binary presence/absence
        "ext_marker": 100,
        "field_null": 100,
        "field_present": 100,
        "list_empty": 100,
        "assignment_present": 100,
        # Strong heuristic — pattern match
        "pattern_match": 85,
        "name_match": 90,
        # Moderate heuristic — keyword
        "keyword_match": 60,
        # Weak heuristic — threshold
        "threshold_exceeded": 75,
    }

    score = base_scores.get(signal_type, 60)

    # Adjustments
    if signals.get("corroborated"):
        score = min(100, score + 10)
    if signals.get("name_only"):
        score = max(0, score - 10)
    if signals.get("no_role_data"):
        score = max(0, score - 15)

    rationale = _confidence_rationale(signal_type, score, signals)
    label = confidence_from_score(score)

    return label, score, rationale


def _confidence_rationale(signal_type: str, score: int, signals: Dict[str, bool]) -> str:
    """Build confidence rationale text."""
    rationales = {
        "ext_marker": "Standard marker for external/guest identity. Deterministic.",
        "field_null": "Field explicitly null in export. Absence confirmed.",
        "field_present": "Field directly present and readable in export.",
        "list_empty": "List field confirmed empty in export.",
        "assignment_present": "Assignment record exists in export. Direct evidence.",
        "pattern_match": "Name matches regex pattern. Strong indicator.",
        "name_match": "Name contains indicator keyword.",
        "keyword_match": "Keyword detected in name. Confidence reduced due to lack of role data.",
        "threshold_exceeded": "Count exceeds threshold. Heuristic-based detection.",
    }

    base = rationales.get(signal_type, "Signal detected from export data.")

    if signals.get("no_role_data"):
        base += " Role data unavailable — confidence reduced."

    return base


# ═══════════════════════════════════════════════════════════════════════════════
# Risk Scoring
# ═══════════════════════════════════════════════════════════════════════════════

def compute_risk_score(
    severity: str,
    confidence_label: str,
    exposure_key: str,
    exploitability_key: str,
) -> float:
    """
    Four-factor risk score.

    Risk = severity_weight × confidence_multiplier × asset_exposure × exploitability
    Normalized to 0-100.

    Called separately from normalize_finding() so that normalization
    and risk calculation remain independent responsibilities.
    """
    sev_weight = SEVERITY_WEIGHT.get(severity, 5)
    _, conf_mul = CONFIDENCE_SCORE.get(confidence_label, (60, 0.70))
    exposure = ASSET_EXPOSURE.get(exposure_key, 0.8)
    exploit = EXPLOITABILITY.get(exploitability_key, 0.7)

    raw = sev_weight * conf_mul * exposure * exploit
    return round(min(raw, 100), 1)


# ═══════════════════════════════════════════════════════════════════════════════
# Finding Normalization
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_finding(raw: Dict, tool_name: str) -> Dict:
    """
    Convert raw finding dict to THRAGG standard schema.

    Responsibility: schema standardization only.
    Risk scoring is a separate step — call compute_risk_score() after this.

    Typical usage:
        finding = normalize_finding(raw, tool_name)
        finding["risk_score"] = compute_risk_score(
            finding["severity"],
            finding["confidence"],
            exposure_key,
            exploitability_key,
        )

    Adds:
    - rule_version (if missing, defaults to "1.0")
    - tool (from parameter)
    - mitre (resolved from mitre_key if present)
    """
    # Resolve MITRE if key provided
    mitre_key = raw.get("mitre_key")
    mitre_data = resolve_mitre(mitre_key) if mitre_key else None

    return {
        # Identity
        "rule_id": raw.get("rule_id"),
        "rule_version": raw.get("rule_version", "1.0"),
        "title": raw.get("title"),
        # Classification
        "severity": raw.get("severity", "Informational"),
        "confidence": raw.get("confidence", "Medium"),
        "confidence_score": raw.get("confidence_score"),
        "confidence_rationale": raw.get("confidence_rationale"),
        "category": raw.get("category"),
        # Asset
        "asset": raw.get("asset"),
        "user": raw.get("user"),
        "role": raw.get("role"),
        # Source
        "source": raw.get("source"),
        "object_id": raw.get("object_id"),
        "tool": tool_name,
        # MITRE
        "mitre": mitre_data,
        "cwe": raw.get("cwe"),
        # Evidence
        "evidence": raw.get("evidence", {}),
        # Recommendation
        "recommendation": raw.get("recommendation"),
        # Risk score is intentionally absent here.
        # Caller applies compute_risk_score() as a separate step.
        "risk_score": None,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK Resolution
#
# v2 improvement:
# Move MITRE_TECHNIQUES into data/mitre.json
# and load at startup. Keeps base.py free of data blobs.
# ═══════════════════════════════════════════════════════════════════════════════

MITRE_TECHNIQUES = {
    "valid_accounts": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
    },
    "account_discovery": {
        "technique_id": "T1087",
        "technique": "Account Discovery",
        "tactic": "Discovery",
    },
    "modify_auth": {
        "technique_id": "T1556",
        "technique": "Modify Authentication Process",
        "tactic": "Credential Access, Defense Evasion, Persistence",
    },
    "steal_token": {
        "technique_id": "T1528",
        "technique": "Steal Application Access Token",
        "tactic": "Credential Access",
    },
    "create_account": {
        "technique_id": "T1136",
        "technique": "Create Account",
        "tactic": "Persistence",
    },
    "cloud_accounts": {
        "technique_id": "T1078.004",
        "technique": "Valid Accounts: Cloud Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
    },
    "persistence_accounts": {
        "technique_id": "T1098",
        "technique": "Account Manipulation",
        "tactic": "Persistence, Privilege Escalation",
    },
    "app_access_token": {
        "technique_id": "T1550.001",
        "technique": "Use Alternate Authentication Material: Application Access Token",
        "tactic": "Defense Evasion, Lateral Movement",
    },
    "oauth_abuse": {
        "technique_id": "T1550.001",
        "technique": "Use Alternate Authentication Material: Application Access Token",
        "tactic": "Defense Evasion, Lateral Movement",
    },
    "service_principal_abuse": {
        "technique_id": "T1528",
        "technique": "Steal Application Access Token",
        "tactic": "Credential Access",
    },
    "excessive_permissions": {
        "technique_id": "T1078",
        "technique": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
    },
    "guest_abuse": {
        "technique_id": "T1078.004",
        "technique": "Valid Accounts: Cloud Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
    },
    "privilege_escalation": {
        "technique_id": "T1078.004",
        "technique": "Valid Accounts: Cloud Accounts",
        "tactic": "Privilege Escalation",
    },
}


def resolve_mitre(mitre_key: str) -> Optional[Dict]:
    """Resolve MITRE key to full technique + tactic dict."""
    return MITRE_TECHNIQUES.get(mitre_key)


# ═══════════════════════════════════════════════════════════════════════════════
# File Handling
# ═══════════════════════════════════════════════════════════════════════════════

def collect_files(
    input_path: str,
    supported_formats: set,
    errors: List[str],
    recursive: bool = True,
    ignored_extensions: Optional[set] = None,
) -> List[str]:
    """
    Collect supported files.

    Supports:
    - single file
    - folders
    - recursive search
    - ignored extensions
    """
    ignored_extensions = ignored_extensions or set()
    files = []

    if os.path.isfile(input_path):
        ext = os.path.splitext(input_path)[1].lower()
        if ext in supported_formats and ext not in ignored_extensions:
            files.append(input_path)
        else:
            errors.append(f"Unsupported file: {input_path}")
        return files

    if os.path.isdir(input_path):
        if recursive:
            walker = os.walk(input_path)
        else:
            walker = [
                (
                    input_path,
                    [],
                    os.listdir(input_path),
                )
            ]

        for root, _, filenames in walker:
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                if ext in supported_formats and ext not in ignored_extensions:
                    files.append(os.path.join(root, name))

        if not files:
            errors.append(f"No supported files found under: {input_path}")

        return sorted(files)

    errors.append(f"Input path is neither file nor folder: {input_path}")
    return []


def load_json_file(filepath: str) -> Tuple[Optional[Any], Optional[str]]:
    """
    Load and parse JSON file.

    Returns:
        (data, error_message)
        If success: (data, None)
        If error: (None, error_message)
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read().strip()
    except Exception as exc:
        return None, f"Could not read {filepath}: {exc}"

    if not raw:
        return None, f"File is empty: {filepath}"

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"Invalid JSON in {filepath}: {exc}"

    return data, None


def validate_file_structure(data: Any, expected_keys: set) -> bool:
    """
    Validate that data dict/list contains expected structure.

    For list: check first element.
    For dict: check presence of keys.
    """
    if isinstance(data, list):
        if not data:
            return False
        sample = data[0]
    else:
        sample = data

    if not isinstance(sample, dict):
        return False

    keys = set(sample.keys())
    return bool(keys & expected_keys)


# ═══════════════════════════════════════════════════════════════════════════════
# Summary Building
# ═══════════════════════════════════════════════════════════════════════════════

def build_summary(
    findings: List[Dict],
    rule_stats: Optional[Dict] = None,
    extra_summary: Optional[Dict] = None,
) -> Dict:
    """
    Build standard THRAGG summary.

    Args:
        findings: List of normalized findings.
        rule_stats: Dict of rule_id -> count (optional).
        extra_summary: Module-specific summary fields merged in at the end (optional).

    Returns:
        Summary dict with severity counts, top category, rule stats, etc.
    """
    rule_stats = rule_stats or {}
    extra_summary = extra_summary or {}

    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
    }

    category_counts = {}

    for finding in findings:
        sev = finding.get("severity", "Informational")
        if sev in severity_counts:
            severity_counts[sev] += 1

        cat = finding.get("category")
        if cat:
            category_counts[cat] = category_counts.get(cat, 0) + 1

    severity_order = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Informational",
    ]

    highest_severity = next(
        (
            sev
            for sev in severity_order
            if severity_counts.get(sev, 0) > 0
        ),
        None,
    )

    top_category = (
        max(category_counts.items(), key=lambda x: x[1])[0]
        if category_counts
        else None
    )

    most_fired_rule = (
        max(rule_stats.items(), key=lambda x: x[1])[0]
        if rule_stats
        else None
    )

    summary = {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "highest_severity": highest_severity,
        "top_category": top_category,
        "most_fired_rule": most_fired_rule,
        "rule_statistics": rule_stats,
    }

    summary.update(extra_summary)

    return summary


# ═══════════════════════════════════════════════════════════════════════════════
# Result Building
# ═══════════════════════════════════════════════════════════════════════════════

def build_result(metadata: Dict) -> Dict:
    """
    Build empty THRAGG result container.

    details and artifacts are intentionally empty dicts.
    Each module populates its own structure via build_empty_details().
    """
    return {
        "metadata": metadata,
        "summary": {},
        "details": {},
        "artifacts": {},
        "errors": [],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Rule Statistics
# ═══════════════════════════════════════════════════════════════════════════════

def build_rule_statistics(findings: List[Dict]) -> Dict[str, int]:
    """Count findings by rule_id."""
    stats = {}
    for finding in findings:
        rule_id = finding.get("rule_id")
        if rule_id:
            stats[rule_id] = stats.get(rule_id, 0) + 1
    return stats


# ═══════════════════════════════════════════════════════════════════════════════
# Module Health
# ═══════════════════════════════════════════════════════════════════════════════

def build_module_health(data_store: Dict[str, List]) -> Dict[str, str]:
    """
    Determine health status for each data type.

    Returns:
        Dict of data_type -> "PASS" or "WARNING"
    """
    health = {}
    for key, val in data_store.items():
        health[key] = "PASS" if val else "WARNING"
    return health


# ═══════════════════════════════════════════════════════════════════════════════
# Processing Statistics
# ═══════════════════════════════════════════════════════════════════════════════

def build_processing_stats(data_store: Dict[str, List]) -> Dict[str, int]:
    """Count objects parsed by type."""
    stats = {}
    for key, val in data_store.items():
        if isinstance(val, list):
            stats[f"{key}_parsed"] = len(val)
        else:
            stats[f"{key}_parsed"] = 1 if val else 0
    return stats


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline Tracking
#
# v2 improvement: pipeline.add() will accept stage metadata:
#   pipeline.add(stage="rules", processed=67, duration=0.34)
# Do not assume entries are always plain strings in future modules.
# ═══════════════════════════════════════════════════════════════════════════════

class Pipeline:
    """Track execution stages."""

    def __init__(self):
        self.stages = []

    def add(self, stage: str):
        """
        Add stage to pipeline.

        Currently accepts a plain string.
        v2: will accept structured stage metadata dict.
        Do not assume this is always a string in consuming code.
        """
        self.stages.append(stage)

    def to_list(self) -> List:
        """Return pipeline as list."""
        return self.stages


# ═══════════════════════════════════════════════════════════════════════════════
# Details Structure Builder
# ═══════════════════════════════════════════════════════════════════════════════

def build_empty_details(*sections: str) -> Dict[str, List]:
    """
    Create empty details structure.

    Each module defines its own sections. No identity-specific
    knowledge lives in base.py.

    Example usage per module:

        identity.py
            build_empty_details(
                "users",
                "groups",
                "applications",
                "service_principals",
                "rbac",
                "tenant",
            )

        cloud.py
            build_empty_details(
                "vm",
                "storage",
                "keyvault",
                "network",
                "identity",
            )

        logs.py
            build_empty_details(
                "authentication",
                "privilege",
                "network",
            )
    """
    return {section: [] for section in sections}


# ═══════════════════════════════════════════════════════════════════════════════
# Utilities
# ═══════════════════════════════════════════════════════════════════════════════

def safe_get(obj: Dict, *keys, default=None):
    """Safely nested get from dict."""
    for key in keys:
        if isinstance(obj, dict):
            obj = obj.get(key)
        else:
            return default
    return obj if obj is not None else default


def ensure_list(val) -> List:
    """Ensure value is list."""
    if isinstance(val, list):
        return val
    if val is None:
        return []
    return [val]


def ensure_dict(val) -> Dict:
    """Ensure value is dict."""
    if isinstance(val, dict):
        return val
    return {}


def merge_dicts(d1: Dict, d2: Dict) -> Dict:
    """Shallow merge d2 into d1."""
    result = d1.copy()
    result.update(d2)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# Validation
# ═══════════════════════════════════════════════════════════════════════════════

def validate_finding_required_fields(finding: Dict) -> Tuple[bool, Optional[str]]:
    """Validate finding has required THRAGG fields."""
    required = ["rule_id", "title", "severity", "confidence", "category"]
    missing = [f for f in required if not finding.get(f)]

    if missing:
        return False, f"Missing required fields: {', '.join(missing)}"

    valid_severity = ["Critical", "High", "Medium", "Low", "Informational"]
    if finding.get("severity") not in valid_severity:
        return False, f"Invalid severity: {finding.get('severity')}"

    valid_confidence = ["Confirmed", "High", "Medium", "Low"]
    if finding.get("confidence") not in valid_confidence:
        return False, f"Invalid confidence: {finding.get('confidence')}"

    return True, None


# ═══════════════════════════════════════════════════════════════════════════════
# Error Handling
# ═══════════════════════════════════════════════════════════════════════════════

class ThraggError(Exception):
    """Base THRAGG error."""
    pass


class ParserError(ThraggError):
    """Parsing error."""
    pass


class LoaderError(ThraggError):
    """Loading error."""
    pass


class RuleEngineError(ThraggError):
    """Rule engine error."""
    pass


class ModuleError(ThraggError):
    """Module execution error."""
    pass


class ValidationError(ThraggError):
    """Validation error."""
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# Example Usage (for testing)
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Test metadata
    meta = build_metadata("identity", "1.1.0", "Azure / Entra ID", "/path/to/exports")
    print("Metadata:", meta)

    # Test confidence
    conf_label, conf_score, rationale = compute_confidence("field_present")
    print(f"\nConfidence: {conf_label} ({conf_score})")
    print(f"Rationale: {rationale}")

    # Test risk score — called independently from normalize_finding()
    risk = compute_risk_score("High", "Confirmed", "tenant", "moderate")
    print(f"\nRisk Score: {risk}")

    # Test normalize then risk — correct usage pattern
    raw_finding = {
        "rule_id": "ID-001",
        "title": "Test Finding",
        "severity": "High",
        "confidence": "Confirmed",
        "category": "identity hygiene",
    }
    finding = normalize_finding(raw_finding, "Azure / Entra ID")
    finding["risk_score"] = compute_risk_score(
        finding["severity"],
        finding["confidence"],
        "tenant",
        "moderate",
    )
    print(f"\nNormalized finding risk_score: {finding['risk_score']}")

    # Test MITRE resolution
    mitre = resolve_mitre("valid_accounts")
    print(f"\nMITRE: {mitre}")

    # Test build_empty_details
    details = build_empty_details("users", "groups", "applications")
    print(f"\nEmpty details: {details}")

    # Test utilities
    print(f"\nSafe get: {safe_get({'a': {'b': 'c'}}, 'a', 'b')}")
    print(f"Ensure list: {ensure_list(None)}")
